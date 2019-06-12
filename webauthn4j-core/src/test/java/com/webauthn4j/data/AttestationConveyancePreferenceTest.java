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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ResultOfMethodCallIgnored")
class AttestationConveyancePreferenceTest {

    private JsonConverter jsonConverter = JsonConverter.INSTANCE;

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.create("none")).isEqualTo(AttestationConveyancePreference.NONE),
                () -> assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT),
                () -> assertThat(AttestationConveyancePreference.create("indirect")).isEqualTo(AttestationConveyancePreference.INDIRECT)
        );
    }

    @Test
    void create_test_with_null_value() {
        assertThat(AttestationConveyancePreference.create(null)).isEqualTo(null);
    }

    @Test
    void create_test_with_invalid_value() {
        assertThrows(IllegalArgumentException.class,
                () -> AttestationConveyancePreference.create("invalid")
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.NONE.getValue()).isEqualTo("none"),
                () -> assertThat(AttestationConveyancePreference.DIRECT.getValue()).isEqualTo("direct"),
                () -> assertThat(AttestationConveyancePreference.INDIRECT.getValue()).isEqualTo("indirect")
        );
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"preference\":\"none\"}", TestDTO.class);
        assertThat(dto.preference).isEqualTo(AttestationConveyancePreference.NONE);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"preference\":\"invalid\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AttestationConveyancePreference preference;
    }
}