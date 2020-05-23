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

import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class AndroidSafetyNetAttestationStatementTest {

    @Test
    void validate(@Mock JWS<Response> jwsMock) {
        new AndroidSafetyNetAttestationStatement("dummy", jwsMock).validate();
        assertAll(
                () -> {
                    AndroidSafetyNetAttestationStatement androidSafetyNetAttestationStatement = new AndroidSafetyNetAttestationStatement("dummy", null);
                    assertThrows(ConstraintViolationException.class, androidSafetyNetAttestationStatement::validate);
                },
                () -> {
                    AndroidSafetyNetAttestationStatement androidSafetyNetAttestationStatement = new AndroidSafetyNetAttestationStatement(null, jwsMock);
                    assertThrows(ConstraintViolationException.class, androidSafetyNetAttestationStatement::validate);
                },
                () -> {
                    AndroidSafetyNetAttestationStatement androidSafetyNetAttestationStatement = new AndroidSafetyNetAttestationStatement(null, null);
                    assertThrows(ConstraintViolationException.class, androidSafetyNetAttestationStatement::validate);
                }
        );
    }

    @Test
    void equals_hashCode_test(@Mock JWS<Response> jwsMock) {
        AndroidSafetyNetAttestationStatement instanceA = new AndroidSafetyNetAttestationStatement("dummy", jwsMock);
        AndroidSafetyNetAttestationStatement instanceB = new AndroidSafetyNetAttestationStatement("dummy", jwsMock);

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
