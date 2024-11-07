/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.verifier.exception.VerificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@SuppressWarnings({"CaughtExceptionImmediatelyRethrown", "ConstantConditions"})
public class WebAuthnManagerSample {

    private final WebAuthnManager webAuthnManager;
    private Logger logger = LoggerFactory.getLogger(WebAuthnManagerSample.class);

    public WebAuthnManagerSample() {
        // WebAuthnManager.createNonStrictWebAuthnManager() returns a WebAuthnManager instance
        // which doesn't validate an attestation statement. It is recommended configuration for most web application.
        // If you are building enterprise web application and need to validate the attestation statement, use the constructor of
        // WebAuthnManager and provide validators you like
        webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();
    }

    public void registration_verify_sample() {

        String registrationResponseJSON = "<registrationResponseJSON>"; /* set registrationResponseJSON received from frontend */
        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parseRegistrationResponseJSON(registrationResponseJSON);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge);

        // expectations
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;

        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);

        try {
            webAuthnManager.verify(registrationData, registrationParameters);
        } catch (VerificationException e) {
            // If you would like to handle WebAuthn data verification error, please catch VerificationException
            throw e;
        }

        // please persist CredentialRecord object, which will be used in the authentication process.
        CredentialRecord credentialRecord =
                new CredentialRecordImpl( // You may create your own CredentialRecord implementation to save friendly authenticator name
                        registrationData.getAttestationObject(),
                        registrationData.getCollectedClientData(),
                        registrationData.getClientExtensions(),
                        registrationData.getTransports()
                );
        save(credentialRecord); // please persist credentialRecord in your manner
    }


    public void authentication_verify_sample() {

        String authenticationResponseJSON = "<authenticationResponseJSON>"; /* set authenticationResponseJSON received from frontend */

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parseAuthenticationResponseJSON(authenticationResponseJSON);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge);

        // expectations
        List<byte[]> allowCredentials = null;
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        CredentialRecord credentialRecord = load(authenticationData.getCredentialId()); // please load authenticator object persisted in the registration process in your manner
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        credentialRecord,
                        allowCredentials,
                        userVerificationRequired,
                        userPresenceRequired
                );

        try {
            webAuthnManager.verify(authenticationData, authenticationParameters);
        } catch (VerificationException e) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }
        // please update the counter of the authenticator record
        updateCounter(
                authenticationData.getCredentialId(),
                authenticationData.getAuthenticatorData().getSignCount()
        );
    }


    private void save(CredentialRecord credentialRecord) {
        // please persist in your manner
    }

    private CredentialRecord load(byte[] credentialId) {
        return null; // please load credentialRecord in your manner
    }

    private void updateCounter(byte[] credentialId, long signCount) {
        // please update the counter of the authenticator record
        // authenticator should be resolved using following comparison:
        // Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId)
    }
}
