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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SuppressWarnings("ConstantConditions")
class AuthenticatorTransportConverterTest {

    private AuthenticatorTransportConverter target;

    @BeforeEach
    void setUp() {
        target = new AuthenticatorTransportConverter();
    }

    @Nested
    class StringToTransportConversionTests {
        @Test
        void shouldConvertStringToTransport() {
            assertThat(target.convert("usb")).isEqualTo(AuthenticatorTransport.USB);
        }

        @Test
        void shouldThrowExceptionWhenInputIsNull() {
            assertThatThrownBy(() -> target.convert(null))
                    .isInstanceOf(DataConversionException.class);
        }

        @Test
        void shouldHandleUnknownValue() {
            assertThat(target.convert("unknown")).isEqualTo(AuthenticatorTransport.create("unknown"));
        }
    }

    @Nested
    class StringSetToTransportSetConversionTests {
        @Test
        void shouldConvertStringSetToTransportSet() {
            assertThat(target.convertSet(Collections.singleton("usb")))
                    .containsExactly(AuthenticatorTransport.USB);
        }

        @Test
        void shouldThrowExceptionWhenInputSetIsNull() {
            assertThatThrownBy(() -> target.convertSet(null))
                    .isInstanceOf(DataConversionException.class);
        }
    }

    @Nested
    class TransportToStringConversionTests {
        @Test
        void shouldConvertTransportToString() {
            assertThat(target.convertToString(AuthenticatorTransport.USB)).isEqualTo("usb");
        }

        @Test
        void shouldThrowExceptionWhenTransportIsNull() {
            assertThatThrownBy(() -> target.convertToString(null))
                    .isInstanceOf(DataConversionException.class);
        }
    }

    @Nested
    class TransportSetToStringSetConversionTests {
        @Test
        void shouldConvertTransportSetToStringSet() {
            assertThat(target.convertSetToStringSet(Collections.singleton(AuthenticatorTransport.USB)))
                    .containsExactly("usb");
        }

        @Test
        void shouldThrowExceptionWhenTransportSetIsNull() {
            assertThatThrownBy(() -> target.convertSetToStringSet(null))
                    .isInstanceOf(DataConversionException.class);
        }
    }
}