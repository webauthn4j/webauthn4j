/*
 * Copyright 2021 the original author or authors.
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

package com.webauthn4j.test.authenticator.webauthn;


import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class PackedAuthenticatorTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final PackedAuthenticator target = new PackedAuthenticator();

    @Test
    void parseOptionsAndMakeCredentials_test() {
        // Mimic getting a PublicKeyCredentialCreationOptions structure from a remote server
        String optionsJson = serialize(new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity("test-rp", "Test RP"),
                new PublicKeyCredentialUserEntity(new byte[32], "test-user", "Test User"),
                new DefaultChallenge(new byte[32]),
                Collections.singletonList(new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256
                ))
        ));

        PublicKeyCredentialCreationOptions options = deserialize(optionsJson);
        assertThatCode(() -> target.makeCredential(new MakeCredentialRequest(
                new byte[32],
                options.getRp(),
                options.getUser(),
                false,
                true,
                false,
                options.getPubKeyCredParams()
                ))).doesNotThrowAnyException();
    }

    @Test
    void makeCredentialsAndGetAssertion_test() {
        final String rpId = "test-rp";
        MakeCredentialResponse response = target.makeCredential(new MakeCredentialRequest(
                new byte[32],
                new PublicKeyCredentialRpEntity(rpId, "Test RP"),
                new PublicKeyCredentialUserEntity(new byte[32], "test-user", "Test User"),
                false,
                true,
                false,
                Collections.singletonList(new PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256
                ))
        ));
        byte[] credentialId = response.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getCredentialId();

        GetAssertionResponse assertion = target.getAssertion(new GetAssertionRequest(rpId,
                new byte[32],
                Collections.singletonList(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY,
                        credentialId, null)),
                true,
                false,
                null));
        assertThat(assertion.getCredentialId()).isEqualTo(credentialId);
    }

    private String serialize(PublicKeyCredentialCreationOptions options) {
        return objectConverter.getJsonConverter().writeValueAsString(options);
    }

    private PublicKeyCredentialCreationOptions deserialize(String json) {
        return objectConverter.getJsonConverter().readValue(json, PublicKeyCredentialCreationOptions.class);
    }
}