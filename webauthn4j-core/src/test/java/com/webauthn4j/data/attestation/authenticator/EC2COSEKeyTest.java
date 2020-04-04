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

package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
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
 * Test for EC2COSEKey
 */
class EC2COSEKeyTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();
    private CborConverter cborConverter = objectConverter.getCborConverter();

    @Test
    void createFromUncompressedECCKey_test() {
        byte[] bytes = Base64UrlUtil.decode("BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        EC2COSEKey key = EC2COSEKey.createFromUncompressedECCKey(bytes);
        assertThat(key.getX()).isEqualTo(Base64UrlUtil.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assertThat(key.getX()).isEqualTo(Base64UrlUtil.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void createFromUncompressedECCKey_with_invalid_length_input_test() {
        assertThrows(IllegalArgumentException.class,
                () -> EC2COSEKey.createFromUncompressedECCKey(new byte[64])
        );
    }

    @Test
    void equals_test() {
        EC2COSEKey instanceA = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey instanceB = TestDataUtil.createEC2COSEPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void cbor_serialize_deserialize_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        COSEKey result = cborConverter.readValue(serialized, COSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        COSEKey result = jsonConverter.readValue(serialized, COSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void validate_test() {
        EC2COSEKey target = TestDataUtil.createEC2COSEPublicKey();
        target.validate();
    }

    @Test
    void validate_with_invalid_algorithm_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey target = new EC2COSEKey(
                null,
                null,
                null,
                Curve.SECP256R1,
                original.getX(),
                original.getY()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_invalid_curve_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey target = new EC2COSEKey(
                null,
                COSEAlgorithmIdentifier.ES256,
                null,
                null,
                original.getX(),
                original.getY()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_invalid_x_test() {
        EC2COSEKey target = createNullXKey();
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }


    @Test
    void validate_with_invalid_y_test() {
        EC2COSEKey target = createNullYKey();
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_from_generated_key_01() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(ECUtil.P_256_SPEC);

        for (int i = 0; i < 1000; i++) {
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            EC2COSEKey ec2CredentialPublicKey = TestDataUtil.createEC2COSEPublicKey((ECPublicKey) publicKey);
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
            EC2COSEKey ec2CredentialPublicKey = TestDataUtil.createEC2COSEPublicKey((ECPublicKey) publicKey);
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
            EC2COSEKey ec2CredentialPublicKey = TestDataUtil.createEC2COSEPublicKey((ECPublicKey) publicKey);
            ec2CredentialPublicKey.validate();
        }
    }

    @Test
    void hasPublicKey_test() {
        EC2COSEKey target = TestDataUtil.createEC2COSEPublicKey();
        assertThat(target.hasPublicKey()).isTrue();
    }

    @Test
    void hasPublicKey_with_invalid_x_test() {
        EC2COSEKey target = createNullXKey();
        assertThat(target.hasPublicKey()).isFalse();
    }

    @Test
    void hasPublicKey_with_invalid_y_test() {
        EC2COSEKey target = createNullYKey();
        assertThat(target.hasPublicKey()).isFalse();
    }

    @Test
    void getPublicKey_test() {
        EC2COSEKey target = TestDataUtil.createEC2COSEPublicKey();
        assertThat(target.getPublicKey()).isNotNull();
    }

    @Test
    void getPublicKey_with_invalid_key_test() {
        EC2COSEKey target = createNullXKey();
        assertThat(target.getPublicKey()).isNull();
    }

    @Test
    void equals_hashCode_test() {
        EC2COSEKey instanceA = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey instanceB = TestDataUtil.createEC2COSEPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    private EC2COSEKey createNullXKey() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        return new EC2COSEKey(
                original.getKeyId(),
                COSEAlgorithmIdentifier.ES256,
                original.getKeyOps(),
                Curve.SECP256R1,
                null,
                original.getY()
        );
    }

    private EC2COSEKey createNullYKey() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        return new EC2COSEKey(
                original.getKeyId(),
                COSEAlgorithmIdentifier.ES256,
                original.getKeyOps(),
                Curve.SECP256R1,
                original.getX(),
                null
        );
    }

}
