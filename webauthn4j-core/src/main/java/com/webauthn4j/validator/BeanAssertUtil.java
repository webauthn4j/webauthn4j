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

package com.webauthn4j.validator;

import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.jetbrains.annotations.Nullable;

/**
 * Per field checker utility class
 */
class BeanAssertUtil {

    private BeanAssertUtil() {
    }

    // ~ Static Methods
    // ========================================================================================================


    public static void validate(@Nullable RegistrationData registrationData) {
        validate((CoreRegistrationData) registrationData);
        validateAuthenticationExtensionsClientOutputs(registrationData.getClientExtensions());
        validate(registrationData.getCollectedClientData());
    }

    public static void validate(@Nullable CoreRegistrationData registrationData) {
        if (registrationData == null) {
            throw new ConstraintViolationException("registrationData must not be null");
        }

        validate(registrationData.getAttestationObject());

        if (registrationData.getAttestationObjectBytes() == null) {
            throw new ConstraintViolationException("attestationObjectBytes must not be null");
        }

        if (registrationData.getClientDataHash() == null) {
            throw new ConstraintViolationException("clientDataHash must not be null");
        }
    }

    public static void validate(@Nullable AuthenticationData authenticationData) {
        validate((CoreAuthenticationData) authenticationData);
        if (authenticationData.getCollectedClientData() == null) {
            throw new ConstraintViolationException("collectedClientData must not be null");
        }
        validate(authenticationData.getCollectedClientData());
        if (authenticationData.getCollectedClientDataBytes() == null) {
            throw new ConstraintViolationException("collectedClientDataBytes must not be null");
        }
        validateAuthenticationExtensionsClientOutputs(authenticationData.getClientExtensions());
    }

    public static void validate(@Nullable CoreAuthenticationData authenticationData) {
        if (authenticationData == null) {
            throw new ConstraintViolationException("authenticationData must not be null");
        }

        if (authenticationData.getCredentialId() == null) {
            throw new ConstraintViolationException("credentialId must not be null");
        }
        if (authenticationData.getSignature() == null) {
            throw new ConstraintViolationException("signature must not be null");
        }
        validate(authenticationData.getAuthenticatorData());
        if (authenticationData.getAuthenticatorDataBytes() == null) {
            throw new ConstraintViolationException("authenticatorDataBytes must not be null");
        }
    }

    public static void validate(@Nullable CollectedClientData collectedClientData) {
        if (collectedClientData == null) {
            throw new ConstraintViolationException("collectedClientData must not be null");
        }
        validate(collectedClientData.getTokenBinding());
    }

    public static void validate(@SuppressWarnings("unused") @Nullable TokenBinding tokenBinding) {
        //nop
    }

    public static void validate(@Nullable AttestationObject attestationObject) {
        if (attestationObject == null) {
            throw new ConstraintViolationException("attestationObject must not be null");
        }
        validate(attestationObject.getAttestationStatement());
        validate(attestationObject.getAuthenticatorData());
    }

    public static <T extends ExtensionAuthenticatorOutput> void validate(@Nullable AuthenticatorData<T> authenticatorData) {
        if (authenticatorData == null) {
            throw new ConstraintViolationException("authenticatorData must not be null");
        }

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
            throw new ConstraintViolationException("rpIdHash must be 32 bytes length");
        }

        long signCount = authenticatorData.getSignCount();
        if (signCount < 0 || signCount > UnsignedNumberUtil.UNSIGNED_INT_MAX) {
            throw new ConstraintViolationException("signCount must be unsigned int");
        }
        AuthenticationExtensionsAuthenticatorOutputs<T> extensions = authenticatorData.getExtensions();
        validateAuthenticatorExtensionsOutputs(extensions);
    }

    public static void validate(@Nullable AttestedCredentialData attestedCredentialData) {
        if (attestedCredentialData == null) {
            throw new ConstraintViolationException("attestedCredentialData must not be null");
        }
        if (attestedCredentialData.getCredentialId() == null) {
            throw new ConstraintViolationException("credentialId must not be null");
        }

        COSEKey coseKey = attestedCredentialData.getCOSEKey();
        validate(coseKey);
    }

    @SuppressWarnings("unused")
    public static <T extends ExtensionClientOutput> void validateAuthenticationExtensionsClientOutputs(
            @Nullable AuthenticationExtensionsClientOutputs<T> authenticationExtensionsClientOutputs) {
        if (authenticationExtensionsClientOutputs == null) {
            return;
        }
        for (T value : authenticationExtensionsClientOutputs.getExtensions().values()) {
            value.validate();
        }
    }

    @SuppressWarnings("unused")
    public static <T extends ExtensionAuthenticatorOutput> void validateAuthenticatorExtensionsOutputs(
            @Nullable AuthenticationExtensionsAuthenticatorOutputs<T> authenticationExtensionsAuthenticatorOutputs) {
        if (authenticationExtensionsAuthenticatorOutputs == null) {
            return;
        }
        for (T value : authenticationExtensionsAuthenticatorOutputs.getExtensions().values()) {
            value.validate();
        }
    }


    public static void validate(@Nullable AttestationStatement attestationStatement) {
        if (attestationStatement == null) {
            throw new ConstraintViolationException("attestationStatement must not be null");
        }
        attestationStatement.validate();
    }

    public static void validate(@Nullable COSEKey coseKey) {
        if (coseKey == null) {
            throw new ConstraintViolationException("coseKey must not be null");
        }
        if (coseKey.getAlgorithm() == null) {
            throw new ConstraintViolationException("coseKey must not be null");
        }
        coseKey.validate();
    }

}
