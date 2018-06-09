/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.ClientExtensionOutputsConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.MaliciousDataException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Validates {@link WebAuthnAuthenticationContext} instance
 */
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final OriginValidator originValidator = new OriginValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final AssertionSignatureValidator assertionSignatureValidator = new AssertionSignatureValidator();

    private final AuthenticatorDataConverter authenticatorDataConverter = new AuthenticatorDataConverter();
    private final CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();
    private final ClientExtensionOutputsConverter clientExtensionOutputsConverter = new ClientExtensionOutputsConverter();
    private final ExtensionValidator extensionValidator = new ExtensionValidator();

    private MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();

    // ~ Methods
    // ========================================================================================================

    public void validate(WebAuthnAuthenticationContext authenticationContext, Authenticator authenticator) {

        BeanAssertUtil.validate(authenticationContext);

        // Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData,
        // and signature respectively.
        byte[] cData = authenticationContext.getClientDataJSON();
        byte[] aData = authenticationContext.getAuthenticatorData();

        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
        // (In the spec, claimed as "C", but use "collectedClientData" here)
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(cData);
        AuthenticatorData authenticatorData = authenticatorDataConverter.convert(aData);
        Map<String, ClientExtensionOutput> clientExtensionOutputs =
                clientExtensionOutputsConverter.convert(authenticationContext.getClientExtensionsJSON());
        ServerProperty serverProperty = authenticationContext.getServerProperty();

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(authenticatorData);
        BeanAssertUtil.validate(serverProperty);

        // Verify that the value of C.type is the string webauthn.get.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.GET)) {
            throw new MaliciousDataException("Bad client data type");
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the authenticator in
        // the PublicKeyCredentialRequestOptions passed to the get() call.
        challengeValidator.validate(collectedClientData, serverProperty);

        // Verify that the value of C.origin matches the Relying Party's origin.
        originValidator.validate(collectedClientData, serverProperty);

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        // which the attestation was obtained. If Token Binding was used on that TLS connection,
        // also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        tokenBindingValidator.validate(collectedClientData.getTokenBinding(), serverProperty.getTokenBindingId());

        // Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), serverProperty);

        // If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
        if (authenticationContext.isUserVerificationRequired() && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("User not verified");
        }

        // If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
        if (!authenticationContext.isUserVerificationRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("User not present");
        }

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        // extension outputs in the extensions in authData are as expected, considering the client extension input
        // values that were given as the extensions option in the get() call. In particular, any extension identifier
        // values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        // identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        Map<String, AuthenticatorExtensionOutput> authenticatorExtensionOutputs = authenticatorData.getExtensions();
        List<String> expectedExtensionIdentifiers = authenticationContext.getExpectedExtensionIds();
        extensionValidator.validate(clientExtensionOutputs, authenticatorExtensionOutputs, expectedExtensionIdentifiers);

        // Using the credential public key, validate that sig is a valid signature over
        // the binary concatenation of the authenticatorData and the hash of the collectedClientData.
        assertionSignatureValidator.validate(authenticationContext, authenticator.getAttestedCredentialData().getCredentialPublicKey());

        // If the signature counter value adata.signCount is nonzero or the value stored in conjunction with
        // credential’s id attribute is nonzero, then run the following sub-step:
        long presentedCounter = authenticatorData.getSignCount();
        long storedCounter = authenticator.getCounter();
        if (presentedCounter > 0 || storedCounter > 0) {
            // If the signature counter value adata.signCount is
            // greater than the signature counter value stored in conjunction with credential’s id attribute.
            if (presentedCounter > storedCounter) {
                authenticator.setCounter(presentedCounter);
            }
            // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
            else {
                maliciousCounterValueHandler.maliciousCounterValueDetected(authenticationContext, authenticator);
            }
        }
    }

    public MaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return maliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(MaliciousCounterValueHandler maliciousCounterValueHandler) {
        AssertUtil.notNull(maliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        this.maliciousCounterValueHandler = maliciousCounterValueHandler;
    }
}
