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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyProtectionTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(KeyProtection.create(0x0001)).isEqualTo(KeyProtection.SOFTWARE),
                () -> assertThat(KeyProtection.create(0x0002)).isEqualTo(KeyProtection.HARDWARE),
                () -> assertThat(KeyProtection.create(0x0004)).isEqualTo(KeyProtection.TEE),
                () -> assertThat(KeyProtection.create(0x0008)).isEqualTo(KeyProtection.SECURE_ELEMENT),
                () -> assertThat(KeyProtection.create(0x0010)).isEqualTo(KeyProtection.REMOTE_HANDLE)
        );
    }

    @Test
    void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtection.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)
        );
    }

    @Test
    void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtection.create(-1)
        );
    }

    @Test
    void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtection.create(0x2A1D)
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(KeyProtection.SOFTWARE.getValue()).isEqualTo(0x0001),
                () -> assertThat(KeyProtection.HARDWARE.getValue()).isEqualTo(0x0002),
                () -> assertThat(KeyProtection.TEE.getValue()).isEqualTo(0x0004),
                () -> assertThat(KeyProtection.SECURE_ELEMENT.getValue()).isEqualTo(0x0008),
                () -> assertThat(KeyProtection.REMOTE_HANDLE.getValue()).isEqualTo(0x0010)
        );
    }

    @Test
    void fromInt_test() {
        KeyProtectionTest.TestDTO dto1 = jsonConverter.readValue("{\"key_protection\":1}", KeyProtectionTest.TestDTO.class);
        KeyProtectionTest.TestDTO dto2 = jsonConverter.readValue("{\"key_protection\":2}", KeyProtectionTest.TestDTO.class);
        KeyProtectionTest.TestDTO dto3 = jsonConverter.readValue("{\"key_protection\":4}", KeyProtectionTest.TestDTO.class);
        KeyProtectionTest.TestDTO dto4 = jsonConverter.readValue("{\"key_protection\":8}", KeyProtectionTest.TestDTO.class);
        KeyProtectionTest.TestDTO dto5 = jsonConverter.readValue("{\"key_protection\":16}", KeyProtectionTest.TestDTO.class);

        assertAll(
                () -> assertThat(dto1.key_protection).isEqualTo(KeyProtection.SOFTWARE),
                () -> assertThat(dto2.key_protection).isEqualTo(KeyProtection.HARDWARE),
                () -> assertThat(dto3.key_protection).isEqualTo(KeyProtection.TEE),
                () -> assertThat(dto4.key_protection).isEqualTo(KeyProtection.SECURE_ELEMENT),
                () -> assertThat(dto5.key_protection).isEqualTo(KeyProtection.REMOTE_HANDLE)
        );
    }

    @Test
    void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"key_protection\":123}", KeyProtectionTest.TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public KeyProtection key_protection;
    }


}