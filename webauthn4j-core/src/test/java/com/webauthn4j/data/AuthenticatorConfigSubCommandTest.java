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

package com.webauthn4j.data;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AuthenticatorConfigSubCommandTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constants_test() {
        assertAll(
                () -> assertThat(AuthenticatorConfigSubCommand.ENABLE_ENTERPRISE_ATTESTATION.getValue()).isEqualTo(0x01),
                () -> assertThat(AuthenticatorConfigSubCommand.TOGGLE_ALWAYS_UV.getValue()).isEqualTo(0x02),
                () -> assertThat(AuthenticatorConfigSubCommand.SET_MIN_PIN_LENGTH.getValue()).isEqualTo(0x03),
                () -> assertThat(AuthenticatorConfigSubCommand.ENABLE_LONG_TOUCH_FOR_RESET.getValue()).isEqualTo(0x04),
                () -> assertThat(AuthenticatorConfigSubCommand.VENDOR_PROTOTYPE.getValue()).isEqualTo(0xFF)
        );
    }

    @Test
    void create_test() {
        AuthenticatorConfigSubCommand subCommand = AuthenticatorConfigSubCommand.create(0x10);
        assertThat(subCommand.getValue()).isEqualTo(0x10);
    }

    @Test
    void equals_hashCode_test() {
        AuthenticatorConfigSubCommand instanceA = AuthenticatorConfigSubCommand.create(0x01);
        AuthenticatorConfigSubCommand instanceB = new AuthenticatorConfigSubCommand(0x01);
        AuthenticatorConfigSubCommand instanceC = AuthenticatorConfigSubCommand.create(0x02);

        assertThat(instanceA)
                .isEqualTo(AuthenticatorConfigSubCommand.ENABLE_ENTERPRISE_ATTESTATION)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);

        assertThat(instanceA).isNotEqualTo(instanceC);
        assertThat(instanceA).isNotEqualTo(null);
        assertThat(instanceA).isNotEqualTo("string");
    }

    @Test
    void toString_test() {
        assertThat(AuthenticatorConfigSubCommand.ENABLE_ENTERPRISE_ATTESTATION).hasToString("1");
        assertThat(AuthenticatorConfigSubCommand.VENDOR_PROTOTYPE).hasToString("255");
    }

    @Test
    void deserialize_test() {
        TestDTO dto = jsonMapper.readValue("{\"subCommand\":3}", TestDTO.class);
        assertThat(dto.subCommand).isEqualTo(AuthenticatorConfigSubCommand.SET_MIN_PIN_LENGTH);
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"subCommand\":\"invalid\"}", TestDTO.class)
        ).isInstanceOf(InvalidFormatException.class);
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AuthenticatorConfigSubCommand subCommand;
    }
}
