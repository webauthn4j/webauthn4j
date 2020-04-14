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
import com.webauthn4j.util.RSAUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for RSACOSEKey
 */
class RSACOSEKeyTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();
    private CborConverter cborConverter = objectConverter.getCborConverter();

    @Test
    void create_with_alg_test(){
        RSACOSEKey key;
        key = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
        key = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
        key = RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
    }

    @Test
    void create_with_null_keyPair_test(){
        assertThatThrownBy(()->{
            RSACOSEKey.create((KeyPair)null, COSEAlgorithmIdentifier.RS256);
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_hashCode_test() {
        RSACOSEKey instanceA = TestDataUtil.createRSACOSEPublicKey();
        RSACOSEKey instanceB = TestDataUtil.createRSACOSEPublicKey();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void cbor_serialize_deserialize_test() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        RSACOSEKey result = cborConverter.readValue(serialized, RSACOSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        RSACOSEKey result = jsonConverter.readValue(serialized, RSACOSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void validate_test() {
        RSACOSEKey target = TestDataUtil.createRSACOSEPublicKey();
        target.validate();
    }

    @Test
    void validate_with_null_algorithm_test() {
        RSACOSEKey target = createNullAlgorithmKey();
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_n_test() {
        RSACOSEKey target = createNullNKey();
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }


    @Test
    void validate_with_null_e_test() {
        RSACOSEKey target = createNullEKey();
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void hasPublicKey_test() {
        RSACOSEKey keyPair = RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS256);
        RSACOSEKey privateKey = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate(), COSEAlgorithmIdentifier.RS256);
        RSACOSEKey publicKey = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic(), COSEAlgorithmIdentifier.RS256);
        assertThat(keyPair.hasPublicKey()).isTrue();
        assertThat(privateKey.hasPublicKey()).isFalse();
        assertThat(publicKey.hasPublicKey()).isTrue();
    }

    @Test
    void hasPrivateKey_test(){
        RSACOSEKey keyPair = RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS256);
        RSACOSEKey privateKey = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate(), COSEAlgorithmIdentifier.RS256);
        RSACOSEKey publicKey = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic(), COSEAlgorithmIdentifier.RS256);
        assertThat(keyPair.hasPrivateKey()).isTrue();
        assertThat(privateKey.hasPrivateKey()).isTrue();
        assertThat(publicKey.hasPrivateKey()).isFalse();
    }

    @Test
    void hasPublicKey_with_null_n_test() {
        RSACOSEKey target = createNullNKey();
        assertThat(target.hasPublicKey()).isFalse();
    }

    @Test
    void hasPublicKey_with_null_e_test() {
        RSACOSEKey target = createNullEKey();
        assertThat(target.hasPublicKey()).isFalse();
    }


    @Test
    void getPublicKey_test(){
        RSACOSEKey keyPair = RSACOSEKey.create(RSAUtil.createKeyPair());
        RSACOSEKey privateKey = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate());
        RSACOSEKey publicKey = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic());
        assertThat(keyPair.getPublicKey()).isNotNull();
        assertThat(privateKey.getPublicKey()).isNull();
        assertThat(publicKey.getPublicKey()).isNotNull();
    }

    @Test
    void getPrivateKey_test(){
        RSACOSEKey keyPair = RSACOSEKey.create(RSAUtil.createKeyPair());
        RSACOSEKey privateKey = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate());
        RSACOSEKey publicKey = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic());
        assertThat(keyPair.getPrivateKey()).isNotNull();
        assertThat(privateKey.getPrivateKey()).isNotNull();
        assertThat(publicKey.getPrivateKey()).isNull();
    }


    @Test
    void getPublicKey_with_invalidKey_test() {
        RSACOSEKey target = createNullNKey();
        assertThat(target.getPublicKey()).isNull();
    }

    private RSACOSEKey createNullAlgorithmKey() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        return new RSACOSEKey(
                original.getKeyId(),
                null,
                original.getKeyOps(),
                original.getN(),
                original.getE()
        );
    }


    private RSACOSEKey createNullNKey() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        return new RSACOSEKey(
                original.getKeyId(),
                original.getAlgorithm(),
                original.getKeyOps(),
                null,
                original.getE()
        );
    }

    private RSACOSEKey createNullEKey() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        return new RSACOSEKey(
                original.getKeyId(),
                original.getAlgorithm(),
                original.getKeyOps(),
                original.getN(),
                null
        );
    }

}
