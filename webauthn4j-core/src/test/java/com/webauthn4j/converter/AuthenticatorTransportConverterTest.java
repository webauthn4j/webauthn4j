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

package com.webauthn4j.converter;


import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.AuthenticatorTransport;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("ConstantConditions")
class AuthenticatorTransportConverterTest {

    private final AuthenticatorTransportConverter converter = new AuthenticatorTransportConverter();


    @Test
    void convert_test() {
        assertThat(converter.convert("usb")).isEqualTo(AuthenticatorTransport.USB);
    }

    @Test
    void convert_null_test() {
        assertThatThrownBy(() -> converter.convert(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void convert_unknown_value_test() {
        assertThat(converter.convert("unknown")).isEqualTo(AuthenticatorTransport.create("unknown"));
    }

    @Test
    void convertSet_test() {
        assertThat(converter.convertSet(Collections.singleton("usb"))).containsExactly(AuthenticatorTransport.USB);
    }

    @Test
    void convertSet_null_test() {
        assertThatThrownBy(() -> converter.convertSet(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void convertToString_test() {
        assertThat(converter.convertToString(AuthenticatorTransport.USB)).isEqualTo("usb");
    }

    @Test
    void convertToString_null_test() {
        assertThatThrownBy(() -> converter.convertToString(null)).isInstanceOf(DataConversionException.class);
    }

    @Test
    void convertSetToStringSet_test() {
        assertThat(converter.convertSetToStringSet(Collections.singleton(AuthenticatorTransport.USB))).containsExactly("usb");
    }

    @Test
    void convertSetToStringSet_null_test() {
        //noinspection ConstantConditions
        assertThatThrownBy(() -> converter.convertSetToStringSet(null)).isInstanceOf(DataConversionException.class);
    }

}