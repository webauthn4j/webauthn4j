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
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

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

    public void registrationValidationSample() {

        // Client properties
        byte[] attestationObject = null /* set attestationObject */;
        byte[] clientDataJSON = null /* set clientDataJSON */;
        String clientExtensionJSON = null;  /* set clientExtensionJSON */
        Set<String> transports = null /* set transports */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        List<PublicKeyCredentialParameters> pubKeyCredParams = null;
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, pubKeyCredParams, userVerificationRequired, userPresenceRequired);
        RegistrationData registrationData;
        try {
            registrationData = webAuthnManager.parse(registrationRequest);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try {
            webAuthnManager.validate(registrationData, registrationParameters);
        } catch (ValidationException e) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }

        // please persist Authenticator object, which will be used in the authentication process.
        Authenticator authenticator =
                new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
                        registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                        registrationData.getAttestationObject().getAttestationStatement(),
                        registrationData.getAttestationObject().getAuthenticatorData().getSignCount()
                );
        save(authenticator); // please persist authenticator in your manner
    }


    public void authenticationValidationSample() {
        // Client properties
        byte[] credentialId = null /* set credentialId */;
        byte[] userHandle = null /* set userHandle */;
        byte[] authenticatorData = null /* set authenticatorData */;
        byte[] clientDataJSON = null /* set clientDataJSON */;
        String clientExtensionJSON = null /* set clientExtensionJSON */;
        byte[] signature = null /* set signature */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        List<byte[]> allowCredentials = null;
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;

        Authenticator authenticator = load(credentialId); // please load authenticator object persisted in the registration process in your manner

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credentialId,
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        allowCredentials,
                        userVerificationRequired,
                        userPresenceRequired
                );

        AuthenticationData authenticationData;
        try {
            authenticationData = webAuthnManager.parse(authenticationRequest);
        } catch (DataConversionException e) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try {
            webAuthnManager.validate(authenticationData, authenticationParameters);
        } catch (ValidationException e) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }
        // please update the counter of the authenticator record
        updateCounter(
                authenticationData.getCredentialId(),
                authenticationData.getAuthenticatorData().getSignCount()
        );
    }


    private void save(Authenticator authenticator) {
        // please persist in your manner
    }

    private Authenticator load(byte[] credentialId) {
        return null; // please load authenticator in your manner
    }

    private void updateCounter(byte[] credentialId, long signCount) {
        // please update the counter of the authenticator record
        // authenticator should be resolved using following comparison:
        // Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId)
    }
}
