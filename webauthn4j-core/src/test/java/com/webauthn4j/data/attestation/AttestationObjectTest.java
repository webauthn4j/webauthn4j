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

package com.webauthn4j.data.attestation;

import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test for AttestationObject
 */
class AttestationObjectTest {

    @Test
    void getFormat_with_attestationStatement_test() {
        AttestationObject instance = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        assertThat(instance.getFormat()).isEqualTo("fido-u2f");
    }

    @Test
    void equals_hashCode_test() {
        AttestationObject instanceA = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AttestationObject instanceB = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

    @Test
    void toString_test() {
        AttestationObject instance = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        assertThatCode(instance::toString).doesNotThrowAnyException();
    }
}
