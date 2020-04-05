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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AuthenticatorTransportTest {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticatorTransport.create(null)).isEqualTo(null),
                () -> assertThat(AuthenticatorTransport.create("usb")).isEqualTo(AuthenticatorTransport.USB),
                () -> assertThat(AuthenticatorTransport.create("nfc")).isEqualTo(AuthenticatorTransport.NFC),
                () -> assertThat(AuthenticatorTransport.create("ble")).isEqualTo(AuthenticatorTransport.BLE),
                () -> assertThat(AuthenticatorTransport.create("internal")).isEqualTo(AuthenticatorTransport.INTERNAL)
        );
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
    void deserialize_test() throws IOException {
        TestDTO dto = objectMapper.readValue("{\"transport\":\"usb\"}", TestDTO.class);
        assertThat(dto.transport).isEqualTo(AuthenticatorTransport.USB);
    }

    @Test
    void deserialize_test_with_unknown_value() {
        assertDoesNotThrow(
                () -> objectMapper.readValue("{\"transport\":\"unknown\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticatorTransport transport;
    }
}