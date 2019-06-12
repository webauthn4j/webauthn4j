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
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for RSACredentialPublicKey
 */
class RSACredentialPublicKeyTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = CborConverter.INSTANCE;

    @Test
    void equals_hashCode_test() {
        RSACredentialPublicKey instanceA = TestDataUtil.createRSCredentialPublicKey();
        RSACredentialPublicKey instanceB = TestDataUtil.createRSCredentialPublicKey();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void cbor_serialize_deserialize_test() {
        RSACredentialPublicKey original = TestDataUtil.createRSCredentialPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        RSACredentialPublicKey result = cborConverter.readValue(serialized, RSACredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        RSACredentialPublicKey original = TestDataUtil.createRSCredentialPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        RSACredentialPublicKey result = jsonConverter.readValue(serialized, RSACredentialPublicKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void validate_test() {
        RSACredentialPublicKey target = TestDataUtil.createRSCredentialPublicKey();
        target.validate();
    }

    @Test
    void validate_with_null_algorithm_test() {
        RSACredentialPublicKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACredentialPublicKey target = new RSACredentialPublicKey(
                null,
                null,
                null,
                null,
                original.getN(),
                original.getE()
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }

    @Test
    void validate_with_null_n_test() {
        RSACredentialPublicKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACredentialPublicKey target = new RSACredentialPublicKey(
                null,
                original.getAlgorithm(),
                null,
                null,
                null,
                original.getE()
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }

    @Test
    void validate_with_null_e_test() {
        RSACredentialPublicKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACredentialPublicKey target = new RSACredentialPublicKey(
                null,
                original.getAlgorithm(),
                null,
                null,
                original.getN(),
                null
        );
        assertThrows(ConstraintViolationException.class,
                () -> target.validate()
        );
    }
}
