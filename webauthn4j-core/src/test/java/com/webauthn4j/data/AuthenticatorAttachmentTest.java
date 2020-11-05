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
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticatorAttachmentTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AuthenticatorAttachment.create("platform")).isEqualTo(AuthenticatorAttachment.PLATFORM),
                () -> assertThat(AuthenticatorAttachment.create("cross-platform")).isEqualTo(AuthenticatorAttachment.CROSS_PLATFORM)
        );
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void create_null_test() {
        assertThatThrownBy(() -> AuthenticatorAttachment.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_invalid_value_test() {
        assertThrows(IllegalArgumentException.class,
                () -> AuthenticatorAttachment.create("invalid")
        );
    }

    @Test
    void getValue_test() {
        assertThat(AuthenticatorAttachment.PLATFORM.getValue()).isEqualTo("platform");
    }

    @Test
    void deserialize_test() throws IOException {
        TestDTO dto = objectMapper.readValue("{\"attachment\": \"platform\"}", TestDTO.class);
        assertThat(dto.attachment).isEqualTo(AuthenticatorAttachment.PLATFORM);
    }

    @Test
    void deserialize_test_with_invalid() throws IOException {
        assertThrows(InvalidFormatException.class,
                () -> objectMapper.readValue("{\"attachment\": \"invalid\"}", TestDTO.class)
        );
    }

    public static class TestDTO {
        public AuthenticatorAttachment attachment;
    }
}