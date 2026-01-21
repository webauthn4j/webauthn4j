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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.util.RSAUtil;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

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
@SuppressWarnings("ConstantConditions")
class RSACOSEKeyTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void create_with_alg_test() {
        RSACOSEKey key;
        key = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
        key = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
        key = RSACOSEKey.create(RSAUtil.createKeyPair(), COSEAlgorithmIdentifier.RS256);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.RS256);
    }

    @Test
    void create_with_null_keyPair_test() {
        assertThatThrownBy(() -> RSACOSEKey.create((KeyPair) null, COSEAlgorithmIdentifier.RS256)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void toString_test(){
        RSACOSEKey coseKey = cborMapper.readValue(HexUtil.decode("A42259010011B6CFA9E7F7AD25C3D59A3CF730C736DC19E57F08C0F9ABCBE99336409FD07B81E0FBA06079FE643728787068E800BF1B5B3379FC9DDBFF65C804AEE0AC7FF98351F5C22494B510E6F349B8480A3AB6EDF3BB161E6DA3D4A5D31FC93F6410269CF7967588E7CE8D7E02BF4992714A906758EF8001533EB4A7ED446D9497EB5C69493895888A60163EA8C4B63886E5CF5FEFE9A29B44439249E8458F23083553F824A46E16F8FDE64E3C5076B946BC25C58AC8CE358FB4A6F3EB45923FDB2C7674FD0159A8AFC6D6580340E6AF3B038A5AA8C4DB210B522CCAAF67DBE6CC0A0634E1456E7F2B087CAC414E4614687F4BFA03B0E9C6D7B89B319DE55250E41C8121430100012059010100AE3586F13BFD1F8E54074D3C98F5CC0C6B9792524B9A0FDB55F30F0D5CBCBD2196C2BF350464C228C7A1F196F27E5F8B114C7A8389ACBD349EDD0F52E02B0CD4CB461C6E6B3626F02C6A5C06D42636BF7CE0140C0B3540EEDA7F727DF8855C4CB8531BDB18CA81477966D97177F747ABDDF04841CC7E9E447B00C82D3738DA5F4326B473D5FE004D9E35B663512829184DE755E7F4674E92CE67065DD122C4B73959D16A1814BB6C06CB8D49B81BFA8C6091B733D792811D5B3C4B3B76458FA2712896EC2DEFFE1C58132BE54F981CB6A93EA8AB6B04A025231B1999406AD6ADA4E9962C7D43DFC1ACBC7A4193CD80CD1CA14336971355F10709AF985EB321E90103"), RSACOSEKey.class);
        assertThat(coseKey).hasToString("RSACOSEKey(keyId=null, alg=null, n=00AE3586F13BFD1F8E54074D3C98F5CC0C6B9792524B9A0FDB55F30F0D5CBCBD2196C2BF350464C228C7A1F196F27E5F8B114C7A8389ACBD349EDD0F52E02B0CD4CB461C6E6B3626F02C6A5C06D42636BF7CE0140C0B3540EEDA7F727DF8855C4CB8531BDB18CA81477966D97177F747ABDDF04841CC7E9E447B00C82D3738DA5F4326B473D5FE004D9E35B663512829184DE755E7F4674E92CE67065DD122C4B73959D16A1814BB6C06CB8D49B81BFA8C6091B733D792811D5B3C4B3B76458FA2712896EC2DEFFE1C58132BE54F981CB6A93EA8AB6B04A025231B1999406AD6ADA4E9962C7D43DFC1ACBC7A4193CD80CD1CA14336971355F10709AF985EB321E9, e=010001, d=11B6CFA9E7F7AD25C3D59A3CF730C736DC19E57F08C0F9ABCBE99336409FD07B81E0FBA06079FE643728787068E800BF1B5B3379FC9DDBFF65C804AEE0AC7FF98351F5C22494B510E6F349B8480A3AB6EDF3BB161E6DA3D4A5D31FC93F6410269CF7967588E7CE8D7E02BF4992714A906758EF8001533EB4A7ED446D9497EB5C69493895888A60163EA8C4B63886E5CF5FEFE9A29B44439249E8458F23083553F824A46E16F8FDE64E3C5076B946BC25C58AC8CE358FB4A6F3EB45923FDB2C7674FD0159A8AFC6D6580340E6AF3B038A5AA8C4DB210B522CCAAF67DBE6CC0A0634E1456E7F2B087CAC414E4614687F4BFA03B0E9C6D7B89B319DE55250E41C81, p=null, q=null, dP=null, dQ=null, qInv=null)");
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
        byte[] serialized = cborMapper.writeValueAsBytes(original);
        RSACOSEKey result = cborMapper.readValue(serialized, RSACOSEKey.class);
        assertThat(result).usingRecursiveComparison().isEqualTo(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        RSACOSEKey original = TestDataUtil.createRSACOSEPublicKey();
        String serialized = jsonMapper.writeValueAsString(original);
        RSACOSEKey result = jsonMapper.readValue(serialized, RSACOSEKey.class);
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
    void hasPrivateKey_test() {
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
    void getPublicKey_test() {
        RSACOSEKey keyPair = RSACOSEKey.create(RSAUtil.createKeyPair());
        RSACOSEKey privateKey = RSACOSEKey.create((RSAPrivateKey) RSAUtil.createKeyPair().getPrivate());
        RSACOSEKey publicKey = RSACOSEKey.create((RSAPublicKey) RSAUtil.createKeyPair().getPublic());
        assertThat(keyPair.getPublicKey()).isNotNull();
        assertThat(privateKey.getPublicKey()).isNull();
        assertThat(publicKey.getPublicKey()).isNotNull();
    }

    @Test
    void getPrivateKey_test() {
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
