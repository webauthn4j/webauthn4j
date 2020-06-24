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

package com.webauthn4j.data.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.KeyProtectionType;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyProtectionTypeTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(KeyProtectionType.create(0x0001)).isEqualTo(KeyProtectionType.SOFTWARE),
                () -> assertThat(KeyProtectionType.create(0x0002)).isEqualTo(KeyProtectionType.HARDWARE),
                () -> assertThat(KeyProtectionType.create(0x0004)).isEqualTo(KeyProtectionType.TEE),
                () -> assertThat(KeyProtectionType.create(0x0008)).isEqualTo(KeyProtectionType.SECURE_ELEMENT),
                () -> assertThat(KeyProtectionType.create(0x0010)).isEqualTo(KeyProtectionType.REMOTE_HANDLE)
        );
    }

    @Test
    void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtectionType.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)
        );
    }

    @Test
    void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtectionType.create(-1)
        );
    }

    @Test
    void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> KeyProtectionType.create(0x2A1D)
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(KeyProtectionType.SOFTWARE.getValue()).isEqualTo(0x0001),
                () -> assertThat(KeyProtectionType.HARDWARE.getValue()).isEqualTo(0x0002),
                () -> assertThat(KeyProtectionType.TEE.getValue()).isEqualTo(0x0004),
                () -> assertThat(KeyProtectionType.SECURE_ELEMENT.getValue()).isEqualTo(0x0008),
                () -> assertThat(KeyProtectionType.REMOTE_HANDLE.getValue()).isEqualTo(0x0010)
        );
    }

    @Test
    void fromInt_test() {
        KeyProtectionTypeTest.TestDTO dto1 = jsonConverter.readValue("{\"key_protection\":1}", KeyProtectionTypeTest.TestDTO.class);
        KeyProtectionTypeTest.TestDTO dto2 = jsonConverter.readValue("{\"key_protection\":2}", KeyProtectionTypeTest.TestDTO.class);
        KeyProtectionTypeTest.TestDTO dto3 = jsonConverter.readValue("{\"key_protection\":4}", KeyProtectionTypeTest.TestDTO.class);
        KeyProtectionTypeTest.TestDTO dto4 = jsonConverter.readValue("{\"key_protection\":8}", KeyProtectionTypeTest.TestDTO.class);
        KeyProtectionTypeTest.TestDTO dto5 = jsonConverter.readValue("{\"key_protection\":16}", KeyProtectionTypeTest.TestDTO.class);

        assertAll(
                () -> assertThat(dto1.key_protection).isEqualTo(KeyProtectionType.SOFTWARE),
                () -> assertThat(dto2.key_protection).isEqualTo(KeyProtectionType.HARDWARE),
                () -> assertThat(dto3.key_protection).isEqualTo(KeyProtectionType.TEE),
                () -> assertThat(dto4.key_protection).isEqualTo(KeyProtectionType.SECURE_ELEMENT),
                () -> assertThat(dto5.key_protection).isEqualTo(KeyProtectionType.REMOTE_HANDLE)
        );
    }

    @Test
    void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"key_protection\":123}", KeyProtectionTypeTest.TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public KeyProtectionType key_protection;
    }


}