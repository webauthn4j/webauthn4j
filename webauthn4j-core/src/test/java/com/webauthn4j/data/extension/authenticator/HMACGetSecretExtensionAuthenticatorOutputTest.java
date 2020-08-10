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

package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class HMACGetSecretExtensionAuthenticatorOutputTest {

    @Test
    void getIdentifier_test(){
        HMACGetSecretExtensionAuthenticatorOutput target = new HMACGetSecretExtensionAuthenticatorOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getIdentifier()).isEqualTo(HMACGetSecretExtensionAuthenticatorOutput.ID);
    }

    @Test
    void getValue_with_valid_key_test(){
        HMACGetSecretExtensionAuthenticatorOutput target = new HMACGetSecretExtensionAuthenticatorOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThatCode(()->target.getValue("hmacGetSecret")).doesNotThrowAnyException();
    }

    @Test
    void getValue_with_invalid_key_test(){
        HMACGetSecretExtensionAuthenticatorOutput target = new HMACGetSecretExtensionAuthenticatorOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThatThrownBy(()->target.getValue("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validate_test(){
        HMACGetSecretExtensionAuthenticatorOutput target = new HMACGetSecretExtensionAuthenticatorOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_invalid_data_test(){
        HMACGetSecretExtensionAuthenticatorOutput target = new HMACGetSecretExtensionAuthenticatorOutput(null);
        assertThatThrownBy(target::validate).isInstanceOf(ConstraintViolationException.class);
    }

}