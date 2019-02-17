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

package com.webauthn4j.response.attestation.statement;

import com.webauthn4j.util.jws.JWS;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

public class AndroidSafetyNetAttestationStatementTest {

    @SuppressWarnings("unchecked")
    @Test
    public void validate() {
        new AndroidSafetyNetAttestationStatement("dummy", mock(JWS.class)).validate();
        assertThatThrownBy(()->{
            new AndroidSafetyNetAttestationStatement("dummy", null).validate();
        }).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(()->{
            new AndroidSafetyNetAttestationStatement(null, mock(JWS.class)).validate();
        }).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(()->{
            new AndroidSafetyNetAttestationStatement(null, null).validate();
        }).isInstanceOf(ConstraintViolationException.class);

    }

    @Test
    public void equals_hashCode_test(){
        @SuppressWarnings("unchecked")
        JWS<Response> jws = mock(JWS.class);
        AndroidSafetyNetAttestationStatement instanceA = new AndroidSafetyNetAttestationStatement("dummy", jws);
        AndroidSafetyNetAttestationStatement instanceB = new AndroidSafetyNetAttestationStatement("dummy", jws);

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);

    }
}
