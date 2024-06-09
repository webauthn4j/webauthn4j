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

import com.webauthn4j.data.extension.HMACGetSecretInput;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HMACSecretAuthenticationExtensionClientInputTest {

    @Test
    void validate_test(){
        assertThatCode(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[32], new byte[32]))::validate).doesNotThrowAnyException();
        assertThatCode(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[32], null))::validate).doesNotThrowAnyException();
        assertThatCode(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[32]))::validate).doesNotThrowAnyException();
        assertThatThrownBy(new HMACSecretAuthenticationExtensionClientInput(null)::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(null, new byte[32]))::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[32], new byte[16]))::validate).isInstanceOf(ConstraintViolationException.class);
        assertThatThrownBy(new HMACSecretAuthenticationExtensionClientInput(new HMACGetSecretInput(new byte[16]))::validate).isInstanceOf(ConstraintViolationException.class);
    }

}