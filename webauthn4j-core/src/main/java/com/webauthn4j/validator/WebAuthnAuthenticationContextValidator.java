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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.jackson.ObjectMapperUtil;
import com.webauthn4j.validator.assertion.signature.AssertionSignatureValidator;
import com.webauthn4j.validator.exception.MaliciousDataException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import com.webauthn4j.jackson.WebAuthnModule;
import com.webauthn4j.jackson.deserializer.AuthenticatorDataDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static com.webauthn4j.client.CollectedClientData.TYPE_WEBAUTHN_GET;

/**
 * Validates {@link WebAuthnAuthenticationContext} instance
 */
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private AuthenticatorDataDeserializer deserializer;

    private AssertionSignatureValidator assertionSignatureValidator;

    private CollectedClientDataConverter collectedClientDataConverter = new CollectedClientDataConverter();

    private MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();

    public WebAuthnAuthenticationContextValidator(AssertionSignatureValidator assertionSignatureValidator) {
        this.assertionSignatureValidator = assertionSignatureValidator;

        this.deserializer = new AuthenticatorDataDeserializer();
    }

    public void validate(WebAuthnAuthenticationContext webAuthnAuthenticationContext, Authenticator authenticator, boolean userVerificationRequired) {

        // In the spec, claimed as "C"
        CollectedClientData collectedClientData = collectedClientDataConverter.convert(webAuthnAuthenticationContext.getCollectedClientData());
        AuthenticatorData authenticatorData = deserializer.deserialize(webAuthnAuthenticationContext.getAuthenticatorData());
        RelyingParty relyingParty = webAuthnAuthenticationContext.getRelyingParty();

        // Verify that the value of C.type is the string webauthn.get.
        if (!Objects.equals(collectedClientData.getType(), TYPE_WEBAUTHN_GET)) {
            throw new MaliciousDataException("Bad client data type");
        }

        // Verify that the value of C.challenge matches the challenge that was sent to the authenticator in
        // the PublicKeyCredentialRequestOptions passed to the get() call.
        challengeValidator.validate(collectedClientData, relyingParty);

        // Verify that the value of C.origin matches the Relying Party's origin.
        originValidator.validate(collectedClientData, relyingParty);

        // Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over
        // which the attestation was obtained. If Token Binding was used on that TLS connection,
        // also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.
        //TODO: not yet implemented

        // Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.
        rpIdHashValidator.validate(authenticatorData.getRpIdHash(), relyingParty);

        // If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.
        if (userVerificationRequired && !authenticatorData.isFlagUV()) {
            throw new UserNotVerifiedException("User not verified");
        }

        // If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
        if (!userVerificationRequired && !authenticatorData.isFlagUP()) {
            throw new UserNotPresentException("User not present");
        }

        // Verify that the values of the client extension outputs in clientExtensionResults and the authenticator
        // extension outputs in the extensions in authData are as expected, considering the client extension input
        // values that were given as the extensions option in the get() call. In particular, any extension identifier
        // values in the clientExtensionResults and the extensions in authData MUST be also be present as extension
        // identifier values in the extensions member of options, i.e., no extensions are present that were not requested.
        // In the general case, the meaning of "are as expected" is specific to the Relying Party and which extensions are in use.
        // TODO: not yet implemented

        // Using the credential public key, validate that sig is a valid signature over
        // the binary concatenation of the authenticatorData and the hash of the collectedClientData.
        assertionSignatureValidator.verifySignature(webAuthnAuthenticationContext, authenticator.getAttestedCredentialData().getCredentialPublicKey());

        // If the signature counter value adata.signCount is nonzero or the value stored in conjunction with
        // credential’s id attribute is nonzero, then run the following sub-step:
        long presentedCounter = authenticatorData.getCounter();
        long storedCounter = authenticator.getCounter();
        if (presentedCounter > 0 || storedCounter > 0) {
            // If the signature counter value adata.signCount is
            // greater than the signature counter value stored in conjunction with credential’s id attribute.
            if (presentedCounter > storedCounter) {
                authenticator.setCounter(presentedCounter);
            }
            // less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
            else {
                maliciousCounterValueHandler.maliciousCounterValueDetected(webAuthnAuthenticationContext, authenticator);
            }
        }
    }

    public MaliciousCounterValueHandler getMaliciousCounterValueHandler() {
        return maliciousCounterValueHandler;
    }

    public void setMaliciousCounterValueHandler(MaliciousCounterValueHandler maliciousCounterValueHandler) {
        this.maliciousCounterValueHandler = maliciousCounterValueHandler;
    }
}
