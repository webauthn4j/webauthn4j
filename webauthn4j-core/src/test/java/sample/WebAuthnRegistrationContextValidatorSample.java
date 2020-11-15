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
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;

import java.util.Set;

@SuppressWarnings("ConstantConditions")
class RegistrationContextValidatorSample {

    public void registrationValidationSample() {
        // Client properties
        byte[] clientDataJSON = null /* set clientDataJSON */;
        byte[] attestationObject = null /* set attestationObject */;
        Set<String> transports = null /* set transports */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
        boolean userVerificationRequired = false;

        RegistrationRequest registrationRequest = new RegistrationRequest(
                clientDataJSON,
                attestationObject,
                transports
        );
        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty,
                userVerificationRequired
        );

        // WebAuthnManager.createNonStrictWebAuthnManager() returns a WebAuthnManager instance
        // which doesn't validate an attestation statement. It is recommended configuration for most web application.
        // If you are building enterprise web application and need to validate the attestation statement, use the constructor of
        // RegistrationContextValidator and provide validators you like
        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

        RegistrationData response = webAuthnManager.validate(registrationRequest, registrationParameters);

        // please persist Authenticator object, which will be used in the authentication process.
        Authenticator authenticator =
                new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
                        response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                        response.getAttestationObject().getAttestationStatement(),
                        response.getAttestationObject().getAuthenticatorData().getSignCount()
                );
        save(authenticator); // please persist authenticator in your manner
    }


    public void athenticationValidationSample() {
        // Client properties
        byte[] credentialId = null /* set credentialId */;
        byte[] clientDataJSON = null /* set clientDataJSON */;
        byte[] authenticatorData = null /* set authenticatorData */;
        byte[] signature = null /* set signature */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);
        Authenticator authenticator = load(credentialId); // please load authenticator object persisted in the registration process in your manner
        boolean userVerificationRequired = true;

        AuthenticationRequest authenticationRequest =
                new AuthenticationRequest(
                        credentialId,
                        authenticatorData,
                        clientDataJSON,
                        signature
                );
        AuthenticationParameters authenticationParameters =
                new AuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired
                );

        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

        AuthenticationData response = webAuthnManager.validate(authenticationRequest, authenticationParameters);

        // please update the counter of the authenticator record
        updateCounter(
                response.getCredentialId(),
                response.getAuthenticatorData().getSignCount()
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
        // authenticator should be resolved using following comparision:
        // Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId)
    }
}
