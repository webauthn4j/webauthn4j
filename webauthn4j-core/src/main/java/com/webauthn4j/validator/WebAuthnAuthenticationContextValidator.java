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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.exception.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Validates the specified {@link WebAuthnAuthenticationContext} instance
 */
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================

    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final ChallengeValidator challengeValidator = new ChallengeValidator();
    private final OriginValidator originValidator = new OriginValidator();
    private final TokenBindingValidator tokenBindingValidator = new TokenBindingValidator();
    private final RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private final AssertionSignatureValidator assertionSignatureValidator = new AssertionSignatureValidator();
    private final ExtensionValidator extensionValidator = new ExtensionValidator();
    private final List<CustomAuthenticationValidator> customAuthenticationValidators = new ArrayList<>();

    private MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnAuthenticationContextValidator() {
        this(new JsonConverter(), CborConverter.INSTANCE);
    }

    public WebAuthnAuthenticationContextValidator(JsonConverter jsonConverter, CborConverter cborConverter) {
        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");
        AssertUtil.notNull(cborConverter, "cborConverter must not be null");

        this.authenticatorDataConverter = new AuthenticatorDataConverter(cborConverter);
        this.collectedClientDataConverter = new CollectedClientDataConverter(jsonConverter);
        this.authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(jsonConverter);
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * validates WebAuthn authentication request
     *
     * @param authenticationContext authentication context
     * @param authenticator         authenticator to be checked against
     * @return validation result
     * @throws DataConversionException if the input cannot be parsed
     * @throws ValidationException     if the input is not valid from the point of WebAuthn validation steps
     * @throws WebAuthnException       if WebAuthn error occurred
     */
    @SuppressWarnings("squid:RedundantThrowsDeclarationCheck")
    public WebAuthnAuthenticationContextValidationResponse validate(WebAuthnAuthenticationContext authenticationContext, Authenticator authenticator) throws WebAuthnException {

        BeanAssertUtil.validate(authenticationContext);

        byte[] credentialId = authenticationContext.getCredentialId();

        // Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData,
        // and signature respectively.
        byte[] cData = authenticationContext.getClientDataJSON();
        byte[] aData = authenticationContext.getAuthenticatorData();

        // Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.
        // (In the spec, claimed as "C", but use "collectedClientData" here)
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(cData);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataConverter.convert(aData);
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                authenticationExtensionsClientOutputsConverter.convert(authenticationContext.getClientExtensionsJSON());
        ServerProperty serverProperty = authenticationContext.getServerProperty();

        BeanAssertUtil.validate(collectedClientData);
        BeanAssertUtil.validate(authenticatorData);
        BeanAssertUtil.validate(serverProperty);

        validateAuthenticatorData(authenticatorData);

        AuthenticationObject authenticationObject = new AuthenticationObject(
                credentialId, collectedClientData, cData, authenticatorData, aData, clientExtensions, authenticationContext.getServerProperty()
        );


        /// Verify that the value of C.type is the string webauthn.get.
        if (!Objects.equals(collectedClientData.getType(), ClientDataType.GET)) {
            throw new MaliciousDataException("ClientData.type must be 'get' on authentication, but it isn't.");
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
            throw new UserNotVerifiedException("Validator is configured to check user verified, but UV flag in authenticatorData is not set.");
        }

        /// Verify that the User Present bit of the flags in authData is set.
        if (authenticationContext.isUserPresenceRequired() && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("Validator is configured to check user present, but UP flag in authenticatorData is not set.");
        }

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        // extension outputs in the extensions in authData are as expected, considering the client extension input
        // values that were given as the extensions option in the get() call. In particular, any extension identifier
        // values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        // identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs = authenticatorData.getExtensions();
        List<String> expectedExtensionIdentifiers = authenticationContext.getExpectedExtensionIds();
        extensionValidator.validate(clientExtensions, authenticationExtensionsAuthenticatorOutputs, expectedExtensionIdentifiers);

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

        for (CustomAuthenticationValidator customAuthenticationValidator : customAuthenticationValidators) {
            customAuthenticationValidator.validate(authenticationObject);
        }

        return new WebAuthnAuthenticationContextValidationResponse(collectedClientData, authenticatorData, clientExtensions);
    }

    void validateAuthenticatorData(AuthenticatorData authenticatorData) {
        if (authenticatorData.getAttestedCredentialData() != null) {
            throw new ConstraintViolationException("attestedCredentialData must be null on authentication");
        }
    }

    public MaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return maliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(MaliciousCounterValueHandler maliciousCounterValueHandler) {
        AssertUtil.notNull(maliciousCounterValueHandler, "maliciousCounterValueHandler must not be null");
        this.maliciousCounterValueHandler = maliciousCounterValueHandler;
    }

    public List<CustomAuthenticationValidator> getCustomAuthenticationValidators() {
        return customAuthenticationValidators;
    }
}
