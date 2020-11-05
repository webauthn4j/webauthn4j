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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_AT;
import static com.webauthn4j.data.attestation.authenticator.AuthenticatorData.BIT_UP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Created by ynojima on 2017/08/18.
 */
class AuthenticatorDataSerializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CborConverter cborConverter = objectConverter.getCborConverter();

    @Test
    void test() {
        byte[] credentialId = "credentialId".getBytes(StandardCharsets.UTF_8);
        AbstractCOSEKey credentialPublicKey = new EC2COSEKey(null, null, null, null, null, null);

        AAGUID aaguid = AAGUID.ZERO;

        byte[] rpIdHash = new byte[32];
        byte flags = (byte) (BIT_UP | BIT_AT);
        long counter = 325;

        AttestedCredentialData attestationData = new AttestedCredentialData(aaguid, credentialId, credentialPublicKey);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(rpIdHash, flags, counter, attestationData);

        //Given

        //When
        byte[] result = cborConverter.writeValueAsBytes(authenticatorData);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> restored = cborConverter.readValue(result, new TypeReference<AuthenticatorData<RegistrationExtensionAuthenticatorOutput>>() {
        });

        //Then

        assertAll(
                () -> assertThat(restored.getRpIdHash()).isEqualTo(rpIdHash),
                () -> assertThat(restored.getFlags()).isEqualTo(flags),
                () -> assertThat(restored.getSignCount()).isEqualTo(counter),
                () -> assertThat(restored.getAttestedCredentialData()).isNotNull(),
                () -> assertThat(restored.getAttestedCredentialData().getAaguid()).isEqualTo(aaguid),
                () -> assertThat(restored.getAttestedCredentialData().getCredentialId()).isEqualTo(credentialId),
                () -> assertThat(restored.getAttestedCredentialData().getCOSEKey()).isEqualTo(credentialPublicKey),
                () -> assertThat(restored.getExtensions().getKeys().isEmpty()).isTrue()
        );
    }
}
