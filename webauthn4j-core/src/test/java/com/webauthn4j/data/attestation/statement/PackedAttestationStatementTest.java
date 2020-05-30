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

import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PackedAttestationStatementTest {

    @Test
    void validate_test() {
        PackedAttestationStatement packedAttestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement();
        packedAttestationStatement.validate();
    }

    @Test
    void validate_invalid_instance_test() {
        PackedAttestationStatement packedAttestationStatement = new PackedAttestationStatement(null, null, null);
        assertThrows(ConstraintViolationException.class,
                packedAttestationStatement::validate
        );
    }

    @Test
    void equals_and_hashCode_test() {
        PackedAttestationStatement packedAttestationStatementA = TestAttestationStatementUtil.createBasicPackedAttestationStatement();
        PackedAttestationStatement packedAttestationStatementB = TestAttestationStatementUtil.createBasicPackedAttestationStatement();
        assertAll(
                () -> assertThat(packedAttestationStatementA).isEqualTo(packedAttestationStatementB),
                () -> assertThat(packedAttestationStatementA).hasSameHashCodeAs(packedAttestationStatementB)
        );
    }
}
