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
import com.webauthn4j.WebAuthnRegistrationContext;
import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.TokenBinding;
import com.webauthn4j.extension.ExtensionOutput;
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.validator.exception.BadRpIdException;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Map;

class BeanAssertUtil {

    private BeanAssertUtil() {
    }

    public static void validate(WebAuthnAuthenticationContext webAuthnAuthenticationContext) {

        if(webAuthnAuthenticationContext == null){
            throw new ConstraintViolationException("webAuthnAuthenticationContext must not be null");
        }
        if (webAuthnAuthenticationContext.getCredentialId() == null) {
            throw new ConstraintViolationException("credentialId must not be null");
        }
        if (webAuthnAuthenticationContext.getClientDataJSON() == null) {
            throw new ConstraintViolationException("clientDataJSON must not be null");
        }
        if (webAuthnAuthenticationContext.getAuthenticatorData() == null) {
            throw new ConstraintViolationException("authenticatorData must not be null");
        }
        if (webAuthnAuthenticationContext.getSignature() == null) {
            throw new ConstraintViolationException("signature must not be null");
        }
        if (webAuthnAuthenticationContext.getServerProperty() == null) {
            throw new ConstraintViolationException("serverProperty must not be null");
        }
    }

    public static void validate(WebAuthnRegistrationContext webAuthnRegistrationContext) {

        if(webAuthnRegistrationContext == null){
            throw new ConstraintViolationException("webAuthnRegistrationContext must not be null");
        }
        if (webAuthnRegistrationContext.getAttestationObject() == null) {
            throw new ConstraintViolationException("attestationObject must not be null");
        }
        if (webAuthnRegistrationContext.getClientDataJSON() == null) {
            throw new ConstraintViolationException("clientDataJSON must not be null");
        }
        if (webAuthnRegistrationContext.getServerProperty() == null) {
            throw new ConstraintViolationException("serverProperty must not be null");
        }
    }

    public static void validate(CollectedClientData collectedClientData) {
        if(collectedClientData == null){
            throw new ConstraintViolationException("collectedClientData must not be null");
        }
        if (collectedClientData.getType() == null) {
            throw new ConstraintViolationException("type must not be null");
        }
        if (collectedClientData.getChallenge() == null) {
            throw new ConstraintViolationException("challenge must not be null");
        }
        if (collectedClientData.getOrigin() == null) {
            throw new ConstraintViolationException("origin must not be null");
        }
        validate(collectedClientData.getTokenBinding());
    }

    public static void validate(TokenBinding tokenBinding) {
        if (tokenBinding == null) {
            return;
        }
        if (tokenBinding.getStatus() == null) {
            throw new ConstraintViolationException("status must not be null");
        }
    }

    public static void validate(AttestationObject attestationObject) {
        if(attestationObject == null){
            throw new ConstraintViolationException("attestationObject must not be null");
        }
        if (attestationObject.getAttestationStatement() == null) {
            throw new ConstraintViolationException("attestationStatement must not be null");
        }
        if (attestationObject.getAuthenticatorData() == null) {
            throw new ConstraintViolationException("authenticatorData must not be null");
        }
    }

    public static void validate(AuthenticatorData authenticatorData) {

        // attestedCredentialData may be null
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();
        if (attestedCredentialData != null) {
            validate(attestedCredentialData);
        }

        byte[] rpIdHash = authenticatorData.getRpIdHash();
        if (rpIdHash == null) {
            throw new ConstraintViolationException("rpIdHash must not be null");
        }
        if (rpIdHash.length != 32) {
            throw new BadRpIdException("rpIdHash must be 32 bytes length");
        }

        long signCount = authenticatorData.getSignCount();
        if (signCount <= 0 || signCount > UnsignedNumberUtil.UNSIGNED_INT_MAX) {
            throw new ConstraintViolationException("signCount must be unsigned int");
        }
        Map<String, AuthenticatorExtensionOutput> extensions = authenticatorData.getExtensions();
        validateAuthenticatorExtensionsOutputs(extensions);
    }

    public static void validate(AttestedCredentialData attestedCredentialData) {

        byte[] aaGuid = attestedCredentialData.getAaGuid();
        if (aaGuid == null) {
            throw new ConstraintViolationException("aaGuid must not be null");
        }
        if (aaGuid.length != 16) {
            throw new ConstraintViolationException("aaGuid must not be 16 bytes length");
        }

        if (attestedCredentialData.getCredentialId() == null) {
            throw new ConstraintViolationException("credentialId must not be null");
        }

        CredentialPublicKey credentialPublicKey = attestedCredentialData.getCredentialPublicKey();
        if (credentialPublicKey == null) {
            throw new ConstraintViolationException("credentialPublicKey must not be null");
        }
        validate(credentialPublicKey);
    }

    public static void validateClientExtensionsOutputs(Map<String, ClientExtensionOutput> clientExtensionOutputs) {
        if (clientExtensionOutputs == null) {
            return;
        }
        clientExtensionOutputs.forEach(BeanAssertUtil::validate);
    }

    public static void validateAuthenticatorExtensionsOutputs(Map<String, AuthenticatorExtensionOutput> authenticatorExtensionOutputs) {
        if (authenticatorExtensionOutputs == null) {
            return;
        }
        authenticatorExtensionOutputs.forEach(BeanAssertUtil::validate);
    }

    public static void validate(String identifier, ExtensionOutput extensionOutput) {
        if (identifier == null) {
            throw new ConstraintViolationException("identifier must not be null");
        }
        if (!identifier.equals(extensionOutput.getIdentifier())) {
            throw new ConstraintViolationException("identifier must match");
        }
        extensionOutput.validate();
    }

    public static void validate(ServerProperty serverProperty) {
        if (serverProperty.getRpId() == null) {
            throw new ConstraintViolationException("rpId must not be null");
        }
        if (serverProperty.getChallenge() == null) {
            throw new ConstraintViolationException("challenge must not be null");
        }
        if (serverProperty.getOrigin() == null) {
            throw new ConstraintViolationException("origin must not be null");
        }
    }

    public static void validate(AttestationStatement attestationStatement) {
        attestationStatement.validate();
    }

    public static void validate(CredentialPublicKey credentialPublicKey) {
        credentialPublicKey.validate();
    }

}
