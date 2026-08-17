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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import tools.jackson.dataformat.cbor.CBORMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class TPMAttestationStatementTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void constructor_test() {
        // Given
        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement source = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();

        // When
        TPMAttestationStatement tpmAttestationStatement = new TPMAttestationStatement(source.getAlg(), source.getX5c(), source.getSig(), source.getCertInfo(), source.getPubArea());

        // Then
        assertAll(
                () -> assertThat(tpmAttestationStatement.getAlg()).isEqualTo(source.getAlg()),
                () -> assertThat(tpmAttestationStatement.getX5c()).isEqualTo(source.getX5c()),
                () -> assertThat(tpmAttestationStatement.getSig()).isEqualTo(source.getSig()),
                () -> assertThat(tpmAttestationStatement.getCertInfo()).isEqualTo(source.getCertInfo()),
                () -> assertThat(tpmAttestationStatement.getPubArea()).isEqualTo(source.getPubArea())
        );
    }

    @Test
    void validate_test() {
        // Given
        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement source = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        TPMAttestationStatement tpmAttestationStatement = new TPMAttestationStatement(source.getAlg(), new AttestationCertificatePath(), source.getSig(), source.getCertInfo(), source.getPubArea());

        // When
        // Then
        assertThrows(ConstraintViolationException.class, tpmAttestationStatement::validate);
    }

    @Test
    void equals_hashCode_test() {
        // Given
        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceA = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        RegistrationObject registrationObjectB = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceB = (TPMAttestationStatement) registrationObjectB.getAttestationObject().getAttestationStatement();

        // When
        // Then
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void cbor_serialize_uses_ctap2_canonical_key_order_test() {
        // CTAP2 canonical CBOR orders map keys by length, then lexicographically
        // by encoded bytes. For 3-byte string keys, "ver" (0x766572) sorts before
        // "x5c" (0x783563) since 0x76 < 0x78. The serialized map should begin with
        // "alg" (the shortest key, 3 bytes, starting with 0x61).
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement original = (TPMAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();

        byte[] serialized = cborMapper.writeValueAsBytes(original);

        // Verify the map starts correctly
        assertThat(serialized[0] & 0xE0).isEqualTo(0xA0); // CBOR map header
        // First key should be "alg" (3-byte string: 0x63='text(3)', 0x616c67='alg')
        assertThat(serialized[1]).isEqualTo((byte) 0x63); // text string of length 3
        assertThat(serialized[2]).isEqualTo((byte) 0x61); // 'a'
        assertThat(serialized[3]).isEqualTo((byte) 0x6c); // 'l'
        assertThat(serialized[4]).isEqualTo((byte) 0x67); // 'g'
    }
}
