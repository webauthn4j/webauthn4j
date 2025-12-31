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

package com.webauthn4j.converter;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class AttestationCertificatePathConverterTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void shouldSerializeAndDeserializeAttestationCertificatePath() {
        // Given
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(Collections.singletonList(TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()));

        // When
        byte[] cbor = cborMapper.writeValueAsBytes(attestationCertificatePath);
        AttestationCertificatePath restored = cborMapper.readValue(cbor, AttestationCertificatePath.class);

        // Then
        assertThat(restored).isEqualTo(attestationCertificatePath);
    }
}
