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

package com.webauthn4j.converter.util;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.ByteArrayBase64ConverterModule;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class JsonConverterTest {

    private static final JsonConverter jsonConverter = new ObjectConverter().getJsonConverter();

    @Test
    void writeValueAsString_test() {
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");
        String str = jsonConverter.writeValueAsString(converterTestDto);
        assertThat(str).isEqualTo("{\"value\":\"dummy\"}");
    }

    @Test
    void writeValueAsString_with_invalid_dto_test() {
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());
        assertThrows(UncheckedIOException.class, () ->
                jsonConverter.writeValueAsString(converterTestInvalidDto)
        );
    }

    @Test
    void writeValueAsBytes_test() {
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");
        byte[] bytes = jsonConverter.writeValueAsBytes(converterTestDto);
        assertThat(Base64UrlUtil.encodeToString(bytes)).isEqualTo("eyJ2YWx1ZSI6ImR1bW15In0");
    }

    @Test
    void writeValueAsString_null_test() {
        assertThat(jsonConverter.writeValueAsString(null)).isEqualTo("null");
    }

    @Test
    void writeValueAsBytes_with_invalid_dto_test() {
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());
        assertThrows(UncheckedIOException.class, () ->
                jsonConverter.writeValueAsBytes(converterTestInvalidDto)
        );
    }

    @Test
    void byteArray_serialization_test() {
        ByteArrayContainer container = new ByteArrayContainer(new byte[]{(byte) 0xFF, (byte) 0xFD, (byte) 0xFE, (byte) 0xFC});
        String serialized = jsonConverter.writeValueAsString(container);
        assertThat(serialized).isEqualTo("{\"value\":\"__3-_A\"}");
    }

    @Test
    void custom_serialization_module_can_override_default_serializer_test() {
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter customJsonConverter = objectConverter.getJsonConverter();
        customJsonConverter.registerModule(new ByteArrayBase64ConverterModule());
        ByteArrayContainer container = new ByteArrayContainer(new byte[]{(byte) 0xFF, (byte) 0xFD, (byte) 0xFE, (byte) 0xFC});
        String serialized = customJsonConverter.writeValueAsString(container);
        assertThat(serialized).isEqualTo("{\"value\":\"//3+/A\"}");
    }

    static class ByteArrayContainer {
        public byte[] value;

        public ByteArrayContainer(byte[] value) {
            this.value = value;
        }

        public byte[] getValue() {
            return value;
        }
    }

    @Nested
    class readValue {
        @Test
        void test() {
            ConverterTestDto dto = jsonConverter.readValue("{\"value\":\"dummy\"}", ConverterTestDto.class);
            assertThat(dto.getValue()).isEqualTo("dummy");
        }

        @Test
        void null_test() {
            ConverterTestDto dto = jsonConverter.readValue("null", ConverterTestDto.class);
            assertThat(dto).isNull();
        }

        @Test
        void invalid_json_test() {
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue("{value:\"dummy\"}", ConverterTestDto.class)
            );
        }

        @Test
        void fill_null_to_nonNull_field_test() {
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue("{\"value\": null}", NonNullDto.class)
            );
        }

        @Test
        void fill_String_to_Integer_field_test() {
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue("{\"value\": \"invalid\"}", IntegerDto.class)
            );
        }

        @Test
        void TypeReference_test() {
            ConverterTestDto dto = jsonConverter.readValue("{\"value\":\"dummy\"}", new TypeReference<ConverterTestDto>() {
            });
            assertThat(dto.getValue()).isEqualTo("dummy");
        }

        @Test
        void invalid_json_and_TypeReference_test() {
            TypeReference<ConverterTestDto> typeReference = new TypeReference<ConverterTestDto>() {
            };
            assertThrows(DataConversionException.class, () ->
                    jsonConverter.readValue("{value:\"dummy\"}", typeReference)
            );
        }
    }

    static class NonNullDto {
        private final String value;

        @JsonCreator
        public NonNullDto(@NotNull @JsonProperty("value") String value) {
            AssertUtil.notNull(value, "value must not be null");
            this.value = value;
        }

        @JsonGetter
        public String getValue() {
            return value;
        }
    }

    static class IntegerDto {
        private final Integer value;

        @JsonCreator
        public IntegerDto(@NotNull @JsonProperty("value") Integer value) {
            AssertUtil.notNull(value, "value must not be null");
            this.value = value;
        }

        @JsonGetter
        public Integer getValue() {
            return value;
        }
    }
}
