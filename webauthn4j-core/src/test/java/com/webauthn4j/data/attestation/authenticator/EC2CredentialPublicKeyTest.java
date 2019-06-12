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

package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for EC2CredentialPublicKey
 */
class EC2CredentialPublicKeyTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = CborConverter.INSTANCE;

    @Test
    void createFromUncompressedECCKey_test() {
        EC2CredentialPublicKey key = EC2CredentialPublicKey.createFromUncompressedECCKey(TestDataUtil.createECCredentialPublicKey().getBytes());
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
        EC2CredentialPublicKey instanceA = TestDataUtil.createECCredentialPublicKey();
        EC2CredentialPublicKey instanceB = TestDataUtil.createECCredentialPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void cbor_serialize_deserialize_test() {
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        CredentialPublicKey result = cborConverter.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        CredentialPublicKey result = jsonConverter.readValue(serialized, CredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void validate_test() {
        EC2CredentialPublicKey target = TestDataUtil.createECCredentialPublicKey();
        target.validate();
    }

    @Test
    void validate_with_invalid_algorithm_test() {
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
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
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
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
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
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
        EC2CredentialPublicKey original = TestDataUtil.createECCredentialPublicKey();
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

    @Test
    void validate_from_generated_key_01() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ECUtil.P_256_SPEC);

        for (int i = 0; i < 1000; i++) {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            EC2CredentialPublicKey ec2CredentialPublicKey = TestDataUtil.createECCredentialPublicKey((ECPublicKey) publicKey);
            ec2CredentialPublicKey.validate();
        }
    }

    @Test
    void validate_from_generated_key_02() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ECUtil.P_384_SPEC);

        for (int i = 0; i < 1000; i++) {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            EC2CredentialPublicKey ec2CredentialPublicKey = TestDataUtil.createECCredentialPublicKey((ECPublicKey) publicKey);
            ec2CredentialPublicKey.validate();
        }
    }

    @Test
    void validate_from_generated_key_03() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ECUtil.P_521_SPEC);

        for (int i = 0; i < 1000; i++) {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            EC2CredentialPublicKey ec2CredentialPublicKey = TestDataUtil.createECCredentialPublicKey((ECPublicKey) publicKey);
            ec2CredentialPublicKey.validate();
        }
    }
}
