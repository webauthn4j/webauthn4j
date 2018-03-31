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
import com.webauthn4j.webauthn.client.CollectedClientData;
import com.webauthn4j.webauthn.context.RelyingParty;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;
import com.webauthn4j.webauthn.context.validator.assertion.signature.AssertionSignatureValidator;
import com.webauthn4j.webauthn.exception.*;
import com.webauthn4j.webauthn.util.WebAuthnModule;
import com.webauthn4j.webauthn.util.jackson.deserializer.WebAuthnAuthenticatorDataDeserializer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

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

    public WebAuthnAuthenticationContextValidator(AssertionSignatureValidator assertionSignatureValidator) {
        this.assertionSignatureValidator = assertionSignatureValidator;

        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new WebAuthnModule());
        this.deserializer = new WebAuthnAuthenticatorDataDeserializer();
    }

    public void validate(WebAuthnAuthenticationContext webAuthnAuthenticationContext, CredentialPublicKey credentialPublicKey, boolean userVerificationRequired) {

        CollectedClientData collectedClientData = deriveCollectedClientData(new String(webAuthnAuthenticationContext.getCollectedClientData(), StandardCharsets.UTF_8));
        WebAuthnAuthenticatorData authenticatorData = deriveAuthenticatorData(webAuthnAuthenticationContext.getAuthenticatorData());
        RelyingParty relyingParty = webAuthnAuthenticationContext.getRelyingParty();

        if(userVerificationRequired && !authenticatorData.isFlagUV()){
            throw new UserNotVerifiedException("User not verified");
        }

        // Verify that the challenge member of C matches the challenge that was sent to the authenticator
        // in the PublicKeyCredentialRequestOptions passed to the get() call.
        try{
            challengeValidator.validate(collectedClientData, relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadChallengeException e){
            throw new BadChallengeException("Bad challenge", e);
        }

        // Verify that the origin member of the collectedClientData matches the Relying Party's origin.
        try{
            originValidator.validate(collectedClientData, relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadOriginException e){
            throw new BadOriginException("Bad origin", e);
        }

        // Verify that the tokenBindingId member of the collectedClientData (if present) matches the Token Binding ID for
        // the TLS connection over which the signature was obtained.
        //TODO: not yet implemented

        // Verify that the clientExtensions member of the collectedClientData is a proper subset of the extensions
        // requested by the Relying Party and that the authenticatorExtensions in the collectedClientData is also
        // a proper subset of the extensions requested by the Relying Party.
        // TODO: not yet implemented

        // Verify that the RP ID hash in the authenticatorData is the SHA-256 hash of the RP ID
        // expected by the Relying Party.
        try{
            rpIdHashValidator.validate(authenticatorData.getRpIdHash(), relyingParty);
        }
        catch (com.webauthn4j.webauthn.exception.BadRpIdException e){
            throw new BadRpIdException("Bad rpId", e);
        }

        // Using the credential public key, validate that sig is a valid signature over
        // the binary concatenation of the authenticatorData and the hash of the collectedClientData.
        try{
            assertionSignatureValidator.verifySignature(webAuthnAuthenticationContext, credentialPublicKey);
        }
        catch (com.webauthn4j.webauthn.exception.BadSignatureException e){
            throw new BadSignatureException("Bad signature", e);
        }
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
