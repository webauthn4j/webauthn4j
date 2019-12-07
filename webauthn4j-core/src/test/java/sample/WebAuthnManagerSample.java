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

import java.util.Collections;
import java.util.List;
import java.util.Set;

public class WebAuthnManagerSample {

    private Logger logger = LoggerFactory.getLogger(WebAuthnManagerSample.class);

    private WebAuthnManager webAuthnManager;

    public WebAuthnManagerSample(){
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
        String clientExtensionJSON = null;  /* set clientExtensionJSON */;
        Set<String> transports = null /* set transports */;

        // Server properties
        Origin origin = null /* set origin */;
        String rpId = null /* set rpId */;
        Challenge challenge = null /* set challenge */;
        byte[] tokenBindingId = null /* set tokenBindingId */;
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challenge, tokenBindingId);

        // expectations
        boolean userVerificationRequired = false;
        boolean userPresenceRequired = true;
        List<String> expectedExtensionIds = Collections.emptyList();

        WebAuthnRegistrationRequest webAuthnRegistrationRequest = new WebAuthnRegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        WebAuthnRegistrationParameters webAuthnRegistrationParameters = new WebAuthnRegistrationParameters(serverProperty, userVerificationRequired, userPresenceRequired, expectedExtensionIds);
        WebAuthnRegistrationData webAuthnRegistrationData;
        try{
            webAuthnRegistrationData = webAuthnManager.parseRegistrationRequest(webAuthnRegistrationRequest);
        }
        catch (DataConversionException e){
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try{
            webAuthnRegistrationData.validate(webAuthnRegistrationParameters);
        }
        catch (ValidationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }

        // please persist Authenticator object, which will be used in the authentication process.
        Authenticator authenticator =
                new AuthenticatorImpl( // You may create your own Authenticator implementation to save friendly authenticator name
                        webAuthnRegistrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                        webAuthnRegistrationData.getAttestationObject().getAttestationStatement(),
                        webAuthnRegistrationData.getAttestationObject().getAuthenticatorData().getSignCount()
                );
        save(authenticator); // please persist authenticator in your manner
    }


    public void athenticationValidationSample() {
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
        boolean userVerificationRequired = true;
        boolean userPresenceRequired = true;
        List<String> expectedExtensionIds = Collections.emptyList();

        Authenticator authenticator = load(credentialId); // please load authenticator object persisted in the registration process in your manner

        WebAuthnAuthenticationRequest webAuthnAuthenticationRequest =
                new WebAuthnAuthenticationRequest(
                        credentialId,
                        userHandle,
                        authenticatorData,
                        clientDataJSON,
                        clientExtensionJSON,
                        signature
                );
        WebAuthnAuthenticationParameters webAuthnAuthenticationParameters =
                new WebAuthnAuthenticationParameters(
                        serverProperty,
                        authenticator,
                        userVerificationRequired,
                        userPresenceRequired,
                        expectedExtensionIds
                );

        WebAuthnAuthenticationData webAuthnAuthenticationData;
        try{
            webAuthnAuthenticationData = webAuthnManager.parseAuthenticationRequest(webAuthnAuthenticationRequest);
        }
        catch (DataConversionException e){
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e;
        }
        try{
            webAuthnAuthenticationData.validate(webAuthnAuthenticationParameters);
        }
        catch (ValidationException e){
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e;
        }
        // please update the counter of the authenticator record
        updateCounter(
                webAuthnAuthenticationData.getAuthenticatorData().getAttestedCredentialData().getCredentialId(),
                webAuthnAuthenticationData.getAuthenticatorData().getSignCount()
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
    }
}
