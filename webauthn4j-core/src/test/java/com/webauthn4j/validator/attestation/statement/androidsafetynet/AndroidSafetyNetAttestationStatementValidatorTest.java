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

package com.webauthn4j.validator.attestation.statement.androidsafetynet;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.AndroidSafetyNetAuthenticator;
import com.webauthn4j.test.client.ClientPlatform;
import com.webauthn4j.validator.RegistrationObject;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

class AndroidSafetyNetAttestationStatementValidatorTest {

    private final ClientPlatform clientPlatform = EmulatorUtil.createClientPlatform(new AndroidSafetyNetAuthenticator());
    private final AndroidSafetyNetAttestationStatementValidator target = new AndroidSafetyNetAttestationStatementValidator();

    @Test
    void validate_non_AndroidSafetyNetAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject)
        );
    }

    @Test
    void validate_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);

        PublicKeyCredentialParameters publicKeyCredentialParameters = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);

        PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = new PublicKeyCredentialUserEntity();

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput<?>> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions
                = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                publicKeyCredentialUserEntity,
                challenge,
                Collections.singletonList(publicKeyCredentialParameters),
                null,
                Collections.emptyList(),
                authenticatorSelectionCriteria,
                AttestationConveyancePreference.DIRECT,
                extensions
        );
        PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput<?>> publicKeyCredential = clientPlatform.create(credentialCreationOptions);
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObject(publicKeyCredential);
        target.validate(registrationObject);
    }
}
