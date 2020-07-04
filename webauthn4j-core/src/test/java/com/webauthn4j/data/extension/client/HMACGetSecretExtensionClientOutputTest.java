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

import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class HMACGetSecretExtensionClientOutputTest {

    @Test
    void getValue_test(){
        HMACGetSecretExtensionClientOutput target = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThat(target.getValue("hmacGetSecret")).isEqualTo(new HMACGetSecretOutput(new byte[32], new byte[32]));
    }

    @Test
    void getValue_with_invalid_key_test(){
        HMACGetSecretExtensionClientOutput target = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThatThrownBy(()->target.getValue("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validate_test(){
        HMACGetSecretExtensionClientOutput target = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(new byte[32], new byte[32]));
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_invalid_data_test(){
        HMACGetSecretExtensionClientOutput outputWithNull = new HMACGetSecretExtensionClientOutput(null);
        assertThatThrownBy(outputWithNull::validate).isInstanceOf(ConstraintViolationException.class);
        HMACGetSecretExtensionClientOutput outputWithOutput1Null = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(null, new byte[32]));
        assertThatThrownBy(outputWithOutput1Null::validate).isInstanceOf(ConstraintViolationException.class);
        HMACGetSecretExtensionClientOutput outputWithInvalidLength1 = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(new byte[0], new byte[32]));
        assertThatThrownBy(outputWithInvalidLength1::validate).isInstanceOf(ConstraintViolationException.class);
        HMACGetSecretExtensionClientOutput outputWithInvalidLength2 = new HMACGetSecretExtensionClientOutput(new HMACGetSecretOutput(new byte[32], new byte[0]));
        assertThatThrownBy(outputWithInvalidLength2::validate).isInstanceOf(ConstraintViolationException.class);
    }

}