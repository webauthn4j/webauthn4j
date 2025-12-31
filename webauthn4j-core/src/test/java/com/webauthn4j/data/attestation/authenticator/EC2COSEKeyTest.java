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
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for EC2COSEKey
 */
class EC2COSEKeyTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void create_with_alg_test() {
        EC2COSEKey key;
        key = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate(), COSEAlgorithmIdentifier.ES256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ES256);
        key = EC2COSEKey.create((ECPublicKey) ECUtil.createKeyPair().getPublic(), COSEAlgorithmIdentifier.ES256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ES256);
        key = EC2COSEKey.create(ECUtil.createKeyPair(), COSEAlgorithmIdentifier.ES256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ES256);
    }

    @Test
    void create_with_null_keyPair_test() {
        assertThatThrownBy(() -> EC2COSEKey.create((KeyPair) null)).isInstanceOf(IllegalArgumentException.class);
    }

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
        byte[] serialized = cborMapper.writeValueAsBytes(original);
        COSEKey result = cborMapper.readValue(serialized, COSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        String serialized = jsonMapper.writeValueAsString(original);
        COSEKey result = jsonMapper.readValue(serialized, COSEKey.class);
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
        EC2COSEKey keyPair = EC2COSEKey.create(ECUtil.createKeyPair());
        EC2COSEKey privateKey = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey publicKey = EC2COSEKey.create((ECPublicKey) ECUtil.createKeyPair().getPublic());
        assertThat(keyPair.hasPublicKey()).isTrue();
        assertThat(privateKey.hasPublicKey()).isFalse();
        assertThat(publicKey.hasPublicKey()).isTrue();
    }

    @Test
    void hasPrivateKey_test() {
        EC2COSEKey keyPair = EC2COSEKey.create(ECUtil.createKeyPair());
        EC2COSEKey privateKey = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey publicKey = EC2COSEKey.create((ECPublicKey) ECUtil.createKeyPair().getPublic());
        assertThat(keyPair.hasPrivateKey()).isTrue();
        assertThat(privateKey.hasPrivateKey()).isTrue();
        assertThat(publicKey.hasPrivateKey()).isFalse();
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
        EC2COSEKey keyPair = EC2COSEKey.create(ECUtil.createKeyPair());
        EC2COSEKey privateKey = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey publicKey = EC2COSEKey.create((ECPublicKey) ECUtil.createKeyPair().getPublic());
        assertThat(keyPair.getPublicKey()).isNotNull();
        assertThat(privateKey.getPublicKey()).isNull();
        assertThat(publicKey.getPublicKey()).isNotNull();
    }

    @Test
    void getPrivateKey_test() {
        EC2COSEKey keyPair = EC2COSEKey.create(ECUtil.createKeyPair());
        EC2COSEKey privateKey = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey publicKey = EC2COSEKey.create((ECPublicKey) ECUtil.createKeyPair().getPublic());
        assertThat(keyPair.getPrivateKey()).isNotNull();
        assertThat(privateKey.getPrivateKey()).isNotNull();
        assertThat(publicKey.getPrivateKey()).isNull();
    }

    @Test
    void getPrivateKey_with_null_curve_test() {
        EC2COSEKey original = EC2COSEKey.create((ECPrivateKey) ECUtil.createKeyPair().getPrivate());
        EC2COSEKey ec2COSEKey = new EC2COSEKey(
                original.getKeyId(),
                COSEAlgorithmIdentifier.ES256,
                original.getKeyOps(),
                null,
                original.getX(),
                original.getY(),
                original.getD()
        );
        assertThatThrownBy(ec2COSEKey::getPrivateKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getPublicKey_with_invalid_key_test() {
        EC2COSEKey target = createNullXKey();
        assertThat(target.getPublicKey()).isNull();
    }

    @Test
    void getPublicKey_with_null_curve_test() {
        EC2COSEKey original = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey ec2COSEKey = new EC2COSEKey(
                original.getKeyId(),
                COSEAlgorithmIdentifier.ES256,
                original.getKeyOps(),
                null,
                original.getX(),
                original.getY()
        );
        assertThatThrownBy(ec2COSEKey::getPublicKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void equals_hashCode_test() {
        EC2COSEKey instanceA = TestDataUtil.createEC2COSEPublicKey();
        EC2COSEKey instanceB = TestDataUtil.createEC2COSEPublicKey();
        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void getCurve_test() {
        assertThat(EC2COSEKey.getCurve(ECUtil.P_256_SPEC)).isEqualTo(Curve.SECP256R1);
        assertThat(EC2COSEKey.getCurve(ECUtil.P_384_SPEC)).isEqualTo(Curve.SECP384R1);
        assertThat(EC2COSEKey.getCurve(ECUtil.P_521_SPEC)).isEqualTo(Curve.SECP521R1);
        //noinspection ConstantConditions
        assertThatThrownBy(() -> EC2COSEKey.getCurve(null)).isInstanceOf(IllegalArgumentException.class);
        ECParameterSpec mock = mock(ECParameterSpec.class);
        when(mock.getCurve()).thenReturn(mock(EllipticCurve.class));
        assertThatThrownBy(() -> EC2COSEKey.getCurve(mock)).isInstanceOf(IllegalArgumentException.class);
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
