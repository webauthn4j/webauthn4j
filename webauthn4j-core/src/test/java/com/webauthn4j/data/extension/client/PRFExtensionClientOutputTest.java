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

package com.webauthn4j.data.extension.client;

import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class PRFExtensionClientOutputTest {

    @Test
    void validate_with_valid_value() {
        AuthenticationExtensionsPRFOutputs outputs = new AuthenticationExtensionsPRFOutputs(true, null);
        assertThatCode(new PRFExtensionClientOutput(outputs)::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_with_null_value() {
        assertThatThrownBy(new PRFExtensionClientOutput(null)::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void getIdentifier_returns_prf() {
        AuthenticationExtensionsPRFOutputs outputs = new AuthenticationExtensionsPRFOutputs(true, null);
        assertThat(new PRFExtensionClientOutput(outputs).getIdentifier()).isEqualTo("prf");
    }

    @Test
    void getValue_with_valid_key() {
        AuthenticationExtensionsPRFOutputs outputs = new AuthenticationExtensionsPRFOutputs(true, null);
        PRFExtensionClientOutput target = new PRFExtensionClientOutput(outputs);
        assertThat(target.getValue("prf")).isSameAs(outputs);
    }

    @Test
    void getValue_with_invalid_key() {
        AuthenticationExtensionsPRFOutputs outputs = new AuthenticationExtensionsPRFOutputs(true, null);
        PRFExtensionClientOutput target = new PRFExtensionClientOutput(outputs);
        assertThatThrownBy(() -> target.getValue("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

}
