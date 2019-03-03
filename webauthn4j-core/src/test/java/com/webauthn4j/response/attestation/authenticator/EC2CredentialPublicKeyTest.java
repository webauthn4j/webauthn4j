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

package com.webauthn4j.response.attestation.authenticator;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for EC2CredentialPublicKey
 */
class EC2CredentialPublicKeyTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = new CborConverter();

    @Test
    void createFromUncompressedECCKey_test() {
        EC2CredentialPublicKey key = EC2CredentialPublicKey.createFromUncompressedECCKey(TestUtil.createECCredentialPublicKey().getBytes());
        assertThat(key.getX()).isEqualTo(Base64UrlUtil.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assertThat(key.getX()).isEqualTo(Base64UrlUtil.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void createFromUncompressedECCKey_with_invalid_length_input_test() {
        assertThrows(IllegalArgumentException.class,
                () -> EC2CredentialPublicKey.createFromUncompressedECCKey(new byte[64])
        );
    }

    @Test
    void equals_test() {
        EC2CredentialPublicKey instanceA = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey instanceB = TestUtil.createECCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void cbor_serialize_deserialize_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        CredentialPublicKey result = cborConverter.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        CredentialPublicKey result = jsonConverter.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void validate_test() {
        EC2CredentialPublicKey target = TestUtil.createECCredentialPublicKey();
        target.validate();
    }

    @Test
    void validate_with_invalid_algorithm_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                null,
                null,
                null,
                Curve.SECP256R1,
                original.getX(),
                original.getY()
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }

    @Test
    void validate_with_invalid_curve_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                null,
                original.getX(),
                original.getY()
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }

    @Test
    void validate_with_invalid_x_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                null,
                original.getY()
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }

    @Test
    void validate_with_invalid_y_test() {
        EC2CredentialPublicKey original = TestUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey target = new EC2CredentialPublicKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                Curve.SECP256R1,
                original.getX(),
                null
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }
}
