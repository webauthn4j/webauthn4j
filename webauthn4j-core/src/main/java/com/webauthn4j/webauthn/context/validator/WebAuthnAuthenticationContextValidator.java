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

package com.webauthn4j.webauthn.context.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.webauthn4j.webauthn.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import com.webauthn4j.webauthn.authenticator.WebAuthnAuthenticator;
import com.webauthn4j.webauthn.client.CollectedClientData;
import com.webauthn4j.webauthn.context.RelyingParty;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import com.webauthn4j.webauthn.context.validator.assertion.signature.AssertionSignatureValidator;
import com.webauthn4j.webauthn.exception.*;
import com.webauthn4j.webauthn.util.jackson.WebAuthnModule;
import com.webauthn4j.webauthn.util.jackson.deserializer.WebAuthnAuthenticatorDataDeserializer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Validates {@link WebAuthnAuthenticationContext} instance
 */
public class WebAuthnAuthenticationContextValidator {

    //~ Instance fields
    // ================================================================================================
    protected final Log logger = LogFactory.getLog(getClass());

    private ChallengeValidator challengeValidator = new ChallengeValidator();
    private OriginValidator originValidator = new OriginValidator();
    private RpIdHashValidator rpIdHashValidator = new RpIdHashValidator();
    private ObjectMapper objectMapper;
    private WebAuthnAuthenticatorDataDeserializer deserializer;

    private AssertionSignatureValidator assertionSignatureValidator;

    private MaliciousCounterValueHandler maliciousCounterValueHandler = new DefaultMaliciousCounterValueHandler();

    public WebAuthnAuthenticationContextValidator(AssertionSignatureValidator assertionSignatureValidator) {
        this.assertionSignatureValidator = assertionSignatureValidator;

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new WebAuthnModule());
        this.deserializer = new WebAuthnAuthenticatorDataDeserializer();
    }

    public void validate(WebAuthnAuthenticationContext webAuthnAuthenticationContext, WebAuthnAuthenticator authenticator, boolean userVerificationRequired) {

        // In the spec, claimed as "C"
        CollectedClientData collectedClientData = deriveCollectedClientData(new String(webAuthnAuthenticationContext.getCollectedClientData(), StandardCharsets.UTF_8));
        WebAuthnAuthenticatorData authenticatorData = deriveAuthenticatorData(webAuthnAuthenticationContext.getAuthenticatorData());
        RelyingParty relyingParty = webAuthnAuthenticationContext.getRelyingParty();

        // Verify that the value of C.type is the string webauthn.get.
        if(!Objects.equals(collectedClientData.getType(), "webauthn.get")){
            throw new MaliciousAssertionException("Bad client data type");
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
        if(userVerificationRequired && !authenticatorData.isFlagUV()){
            throw new UserNotVerifiedException("User not verified");
        }

        // If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.
        if(!userVerificationRequired && !authenticatorData.isFlagUP()){
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
        if(authenticatorData.getCounter() > 0 || authenticator.getCounter() > 0){
            // If the signature counter value adata.signCount is
            // greater than the signature counter value stored in conjunction with credential’s id attribute.
            if(presentedCounter > storedCounter){
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

    CollectedClientData deriveCollectedClientData(String clientDataJson) {
        try {
            String trimmedClientDataJson = clientDataJson.replace("\0", "").trim();
            return objectMapper.readValue(trimmedClientDataJson, CollectedClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    WebAuthnAuthenticatorData deriveAuthenticatorData(byte[] rawAuthenticatorData) {
        return deserializer.deserialize(rawAuthenticatorData);
    }

}
