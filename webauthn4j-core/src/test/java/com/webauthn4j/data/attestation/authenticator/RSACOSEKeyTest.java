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
 * Test for RSACOSEKey
 */
class RSACOSEKeyTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = new CborConverter();

    @Test
    void equals_hashCode_test() {
        RSACOSEKey instanceA = TestDataUtil.createRSCredentialPublicKey();
        RSACOSEKey instanceB = TestDataUtil.createRSCredentialPublicKey();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void cbor_serialize_deserialize_test() {
        RSACOSEKey original = TestDataUtil.createRSCredentialPublicKey();
        byte[] serialized = cborConverter.writeValueAsBytes(original);
        RSACOSEKey result = cborConverter.readValue(serialized, RSACOSEKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void json_serialize_deserialize_test() {
        RSACOSEKey original = TestDataUtil.createRSCredentialPublicKey();
        String serialized = jsonConverter.writeValueAsString(original);
        RSACOSEKey result = jsonConverter.readValue(serialized, RSACOSEKey.class);
        assertThat(result).isEqualToComparingFieldByFieldRecursively(original);
    }

    @Test
    void validate_test() {
        RSACOSEKey target = TestDataUtil.createRSCredentialPublicKey();
        target.validate();
    }

    @Test
    void validate_with_null_algorithm_test() {
        RSACOSEKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACOSEKey target = new RSACOSEKey(
                null,
                null,
                null,
                original.getN(),
                original.getE()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_n_test() {
        RSACOSEKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACOSEKey target = new RSACOSEKey(
                null,
                original.getAlgorithm(),
                null,
                null,
                original.getE()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_e_test() {
        RSACOSEKey original = TestDataUtil.createRSCredentialPublicKey();
        RSACOSEKey target = new RSACOSEKey(
                null,
                original.getAlgorithm(),
                null,
                original.getN(),
                null
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }
}
