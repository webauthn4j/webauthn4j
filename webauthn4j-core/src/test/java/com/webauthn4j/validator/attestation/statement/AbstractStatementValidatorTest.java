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

package com.webauthn4j.validator.attestation.statement;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.attestation.statement.packed.PackedAttestationStatementValidator;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AbstractStatementValidatorTest {

    private final PackedAttestationStatementValidator packedAttestationStatementValidator = new PackedAttestationStatementValidator();

    @Test
    void getJcaName() {
        COSEAlgorithmIdentifier invalid = COSEAlgorithmIdentifier.create(-16);
        assertThatThrownBy(() -> packedAttestationStatementValidator.getJcaName(invalid)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void supports_with_null_test() {
        CoreRegistrationObject coreRegistrationObject = mock(CoreRegistrationObject.class, Mockito.RETURNS_DEEP_STUBS);
        when(coreRegistrationObject.getAttestationObject().getAttestationStatement()).thenReturn(null);
        assertThat(packedAttestationStatementValidator.supports(coreRegistrationObject)).isFalse();
    }
}