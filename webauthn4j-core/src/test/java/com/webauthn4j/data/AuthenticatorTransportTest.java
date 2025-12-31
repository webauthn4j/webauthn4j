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

package com.webauthn4j.data;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AuthenticatorTransportTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticatorTransport.create("usb")).isEqualTo(AuthenticatorTransport.USB),
                () -> assertThat(AuthenticatorTransport.create("nfc")).isEqualTo(AuthenticatorTransport.NFC),
                () -> assertThat(AuthenticatorTransport.create("ble")).isEqualTo(AuthenticatorTransport.BLE),
                () -> assertThat(AuthenticatorTransport.create("hybrid")).isEqualTo(AuthenticatorTransport.HYBRID),
                () -> assertThat(AuthenticatorTransport.create("internal")).isEqualTo(AuthenticatorTransport.INTERNAL)
        );
    }

    @SuppressWarnings({"ConstantConditions"})
    @Test
    void create_null_test() {
        assertThatThrownBy(() -> AuthenticatorTransport.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getValue_test() {
        assertThat(AuthenticatorTransport.USB.getValue()).isEqualTo("usb");
    }

    @Test
    void create_invalid_value_test() {
        assertDoesNotThrow(
                () -> AuthenticatorTransport.create("unknown")
        );
    }

    @Test
    void deserialize_test() {
        TestDTO dto = jsonMapper.readValue("{\"transport\":\"usb\"}", TestDTO.class);
        assertThat(dto.transport).isEqualTo(AuthenticatorTransport.USB);
    }

    @Test
    void deserialize_test_with_unknown_value() {
        assertDoesNotThrow(
                () -> jsonMapper.readValue("{\"transport\":\"unknown\"}", TestDTO.class)
        );
    }

    @Test
    void deserialize_test_with_invalid_value() {
        // Actually, deserialize method is not used because ObjectMapper does't call custom serializer when type doesn't match (String and int)
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"transport\": -1}", TestDTO.class)
        ).isInstanceOf(MismatchedInputException.class);
    }

    @Test
    void deserialize_test_with_null() {
        // Actually, deserialize method is not used by ObjectMapper because ObjectMapper doesn't call custom deserializer when the value is null
        assertThatThrownBy(
                () -> AuthenticatorTransport.deserialize(null)
        ).isInstanceOf(InvalidFormatException.class);
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticatorTransport transport;
    }
}