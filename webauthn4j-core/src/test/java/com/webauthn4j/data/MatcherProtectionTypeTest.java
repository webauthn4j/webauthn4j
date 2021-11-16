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

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.deserializer.json.MatcherProtectionTypeFromStringDeserializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class MatcherProtectionTypeTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(MatcherProtectionType.create(0x0001)).isEqualTo(MatcherProtectionType.SOFTWARE),
                () -> assertThat(MatcherProtectionType.create(0x0002)).isEqualTo(MatcherProtectionType.TEE),
                () -> assertThat(MatcherProtectionType.create(0x0004)).isEqualTo(MatcherProtectionType.ON_CHIP),
                () -> assertThat(MatcherProtectionType.create("software")).isEqualTo(MatcherProtectionType.SOFTWARE),
                () -> assertThat(MatcherProtectionType.create("tee")).isEqualTo(MatcherProtectionType.TEE),
                () -> assertThat(MatcherProtectionType.create("on_chip")).isEqualTo(MatcherProtectionType.ON_CHIP)
        );
    }

    @Test
    void getValue_test() {
        assertThat(MatcherProtectionType.SOFTWARE.getValue()).isEqualTo(0x0001);
    }

    @Test
    void toString_test() {
        assertThat(MatcherProtectionType.SOFTWARE).hasToString("software");
    }

    @Nested
    class IntSerialization {

        @Test
        void deserialize_test() {
            MatcherProtectionTypeAsIntTestDTO dto = jsonConverter.readValue("{\"matcherProtectionType\": 2}", MatcherProtectionTypeAsIntTestDTO.class);
            assertThat(dto.matcherProtectionType).isEqualTo(MatcherProtectionType.TEE);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"matcherProtectionType\": \"-1\"}", MatcherProtectionTypeAsIntTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"matcherProtectionType\": \"\"}", MatcherProtectionTypeAsIntTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            MatcherProtectionTypeAsIntTestDTO data = jsonConverter.readValue("{\"matcherProtectionType\":null}", MatcherProtectionTypeAsIntTestDTO.class);
            assertThat(data.matcherProtectionType).isNull();
        }

    }

    static class MatcherProtectionTypeAsIntTestDTO {
        @SuppressWarnings("WeakerAccess")
        public MatcherProtectionType matcherProtectionType;
    }

    @Nested
    class StringSerialization {

        @Test
        void deserialize_test() {
            MatcherProtectionTypeAsStringTestDTO dto = jsonConverter.readValue("{\"matcherProtectionType\": \"tee\"}", MatcherProtectionTypeAsStringTestDTO.class);
            assertThat(dto.matcherProtectionType).isEqualTo(MatcherProtectionType.TEE);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"matcherProtectionType\": \"invalid\"}", MatcherProtectionTypeAsStringTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            MatcherProtectionTypeAsStringTestDTO data = jsonConverter.readValue("{\"matcherProtectionType\":null}", MatcherProtectionTypeAsStringTestDTO.class);
            assertThat(data.matcherProtectionType).isNull();
        }

    }

    static class MatcherProtectionTypeAsStringTestDTO {
        @JsonDeserialize(using = MatcherProtectionTypeFromStringDeserializer.class)
        @SuppressWarnings("WeakerAccess")
        public MatcherProtectionType matcherProtectionType;
    }

}