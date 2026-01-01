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

import com.webauthn4j.converter.jackson.deserializer.json.MatcherProtectionTypeFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.MatcherProtectionTypeToStringSerializer;
import com.webauthn4j.converter.util.ObjectConverter;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class MatcherProtectionTypeTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonMapper jsonMapper = objectConverter.getJsonMapper();

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
        void serialize_test(){
            StringSerializationTestDTO dto = new StringSerializationTestDTO();
            dto.matcherProtectionType = MatcherProtectionType.TEE;
            String string = jsonMapper.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"matcherProtectionType\":2}");
        }

        @Test
        void deserialize_test() {
            StringSerializationTestDTO dto = jsonMapper.readValue("{\"matcherProtectionType\":2}", StringSerializationTestDTO.class);
            assertThat(dto.matcherProtectionType).isEqualTo(MatcherProtectionType.TEE);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"matcherProtectionType\": \"-1\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"matcherProtectionType\": \"\"}", StringSerializationTestDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void deserialize_test_with_null() {
            StringSerializationTestDTO data = jsonMapper.readValue("{\"matcherProtectionType\":null}", StringSerializationTestDTO.class);
            assertThat(data.matcherProtectionType).isNull();
        }

    }

    static class StringSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public MatcherProtectionType matcherProtectionType;
    }

    @Nested
    class StringSerialization {

        @Test
        void serialize_test(){
            IntSerializationDTO dto = new IntSerializationDTO();
            dto.matcherProtectionType = MatcherProtectionType.TEE;
            String string = jsonMapper.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"matcherProtectionType\":\"tee\"}");
        }

        @Test
        void deserialize_test() {
            IntSerializationDTO dto = jsonMapper.readValue("{\"matcherProtectionType\":\"tee\"}", IntSerializationDTO.class);
            Assertions.assertThat(dto.matcherProtectionType).isEqualTo(MatcherProtectionType.TEE);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonMapper.readValue("{\"matcherProtectionType\": \"invalid\"}", IntSerializationDTO.class)
            ).isInstanceOf(InvalidFormatException.class);
        }

        @Test
        void deserialize_test_with_null() {
            IntSerializationDTO data = jsonMapper.readValue("{\"matcherProtectionType\":null}", IntSerializationDTO.class);
            Assertions.assertThat(data.matcherProtectionType).isNull();
        }

    }

    static class IntSerializationDTO {
        @JsonSerialize(using = MatcherProtectionTypeToStringSerializer.class)
        @JsonDeserialize(using = MatcherProtectionTypeFromStringDeserializer.class)
        @SuppressWarnings("WeakerAccess")
        public MatcherProtectionType matcherProtectionType;
    }

}