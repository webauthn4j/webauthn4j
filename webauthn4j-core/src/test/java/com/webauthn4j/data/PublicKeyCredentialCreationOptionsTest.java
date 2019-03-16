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

package com.webauthn4j.data;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.util.CollectionUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class PublicKeyCredentialCreationOptionsTest {

    @Test
    void getter_test() {
        String rpId = "example.com";
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(rpId, "valid.site.example.com");
        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity();
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.singletonList(publicKeyCredentialParameters);
        long timeout = 10000;
        List<PublicKeyCredentialDescriptor> excludeCredentials = Collections.emptyList();
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria =
                new AuthenticatorSelectionCriteria(
                        AuthenticatorAttachment.CROSS_PLATFORM,
                        true,
                        UserVerificationRequirement.REQUIRED);
        AttestationConveyancePreference attestation = AttestationConveyancePreference.DIRECT;
        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions = new AuthenticationExtensionsClientInputs<>();
        PublicKeyCredentialCreationOptions credentialCreationOptions = new PublicKeyCredentialCreationOptions(
                rp,
                user,
                challenge,
                pubKeyCredParams,
                timeout,
                excludeCredentials,
                authenticatorSelectionCriteria,
                attestation,
                extensions
        );


        assertAll(
                () -> assertThat(credentialCreationOptions.getRp()).isEqualTo(rp),
                () -> assertThat(credentialCreationOptions.getUser()).isEqualTo(user),
                () -> assertThat(credentialCreationOptions.getChallenge()).isEqualTo(challenge),
                () -> assertThat(credentialCreationOptions.getPubKeyCredParams()).isEqualTo(pubKeyCredParams),
                () -> assertThat(credentialCreationOptions.getTimeout()).isEqualTo(timeout),
                () -> assertThat(credentialCreationOptions.getExcludeCredentials()).isEqualTo(excludeCredentials),
                () -> assertThat(credentialCreationOptions.getAuthenticatorSelection()).isEqualTo(authenticatorSelectionCriteria),
                () -> assertThat(credentialCreationOptions.getAttestation()).isEqualTo(attestation),
                () -> assertThat(credentialCreationOptions.getExtensions()).isEqualTo(extensions)
        );
    }


    @Test
    void equals_hashCode_test() {
        String rpId = "example.com";
        Challenge challenge = new DefaultChallenge();

        PublicKeyCredentialParameters publicKeyCredentialParameters
                = new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256);
        PublicKeyCredentialCreationOptions instanceA = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );
        PublicKeyCredentialCreationOptions instanceB = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity(rpId, "example.com"),
                new PublicKeyCredentialUserEntity(),
                challenge,
                Collections.singletonList(publicKeyCredentialParameters)
        );

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}