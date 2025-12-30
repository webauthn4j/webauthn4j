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
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.jackson.ByteArrayBase64ConverterModule;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class JsonConverterTest {

    private static final JsonConverter jsonConverter = new ObjectConverter().getJsonConverter();

    @Test
    void shouldSerializeObjectToString() {
        //Given
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");

        //When
        String str = jsonConverter.writeValueAsString(converterTestDto);

        //Then
        assertThat(str).isEqualTo("{\"value\":\"dummy\"}");
    }

    @Test
    void shouldThrowExceptionWhenSerializingInvalidObject() {
        //Given
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());

        //When/Then
        assertThrows(DataConversionException.class, () ->
                jsonConverter.writeValueAsString(converterTestInvalidDto)
        );
    }

    @Test
    void shouldSerializeObjectToBytes() {
        //Given
        ConverterTestDto converterTestDto = new ConverterTestDto();
        converterTestDto.setValue("dummy");

        //When
        byte[] bytes = jsonConverter.writeValueAsBytes(converterTestDto);

        //Then
        assertThat(Base64UrlUtil.encodeToString(bytes)).isEqualTo("eyJ2YWx1ZSI6ImR1bW15In0");
    }

    @Test
    void shouldSerializeNullToNullString() {
        //Given

        //When
        String result = jsonConverter.writeValueAsString(null);

        //Then
        assertThat(result).isEqualTo("null");
    }

    @Test
    void shouldThrowExceptionWhenSerializingInvalidObjectToBytes() {
        //Given
        ConverterTestInvalidDto converterTestInvalidDto = new ConverterTestInvalidDto();
        converterTestInvalidDto.setValue(new Object());

        //When/Then
        assertThrows(DataConversionException.class, () ->
                jsonConverter.writeValueAsBytes(converterTestInvalidDto)
        );
    }

    @Test
    void shouldSerializeByteArrayToBase64UrlString() {
        //Given
        ByteArrayContainer container = new ByteArrayContainer(new byte[]{(byte) 0xFF, (byte) 0xFD, (byte) 0xFE, (byte) 0xFC});

        //When
        String serialized = jsonConverter.writeValueAsString(container);

        //Then
        assertThat(serialized).isEqualTo("{\"value\":\"__3-_A\"}");
    }

    @Test
    void shouldOverrideDefaultSerializerWithCustomModule() {
        //Given
        ObjectConverter objectConverter = new ObjectConverter();
        JsonConverter customJsonConverter = objectConverter.getJsonConverter();
        customJsonConverter.registerModule(new ByteArrayBase64ConverterModule());
        ByteArrayContainer container = new ByteArrayContainer(new byte[]{(byte) 0xFF, (byte) 0xFD, (byte) 0xFE, (byte) 0xFC});

        //When
        String serialized = customJsonConverter.writeValueAsString(container);

        //Then
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
        void shouldDeserializeJsonToObject() {
            //Given
            String json = "{\"value\":\"dummy\"}";

            //When
            ConverterTestDto dto = jsonConverter.readValue(json, ConverterTestDto.class);

            //Then
            assertThat(dto.getValue()).isEqualTo("dummy");
        }

        @Test
        void shouldReturnNullForNullJson() {
            //Given
            String json = "null";

            //When
            ConverterTestDto dto = jsonConverter.readValue(json, ConverterTestDto.class);

            //Then
            assertThat(dto).isNull();
        }

        @Test
        void shouldThrowExceptionForInvalidJson() {
            //Given
            String invalidJson = "{value:\"dummy\"}";

            //When/Then
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue(invalidJson, ConverterTestDto.class)
            );
        }

        @Test
        void shouldThrowExceptionWhenNullValueProvidedForNonNullField() {
            //Given
            String json = "{\"value\": null}";

            //When/Then
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue(json, NonNullDto.class)
            );
        }

        @Test
        void shouldThrowExceptionWhenStringValueProvidedForIntegerField() {
            //Given
            String json = "{\"value\": \"invalid\"}";

            //When/Then
            assertThrows(DataConversionException.class,
                    () -> jsonConverter.readValue(json, IntegerDto.class)
            );
        }

        @Test
        void shouldDeserializeJsonToObjectUsingTypeReference() {
            //Given
            String json = "{\"value\":\"dummy\"}";

            //When
            ConverterTestDto dto = jsonConverter.readValue(json, new TypeReference<ConverterTestDto>() {
            });

            //Then
            assertThat(dto.getValue()).isEqualTo("dummy");
        }

        @Test
        void shouldThrowExceptionForInvalidJsonWithTypeReference() {
            //Given
            String invalidJson = "{value:\"dummy\"}";
            TypeReference<ConverterTestDto> typeReference = new TypeReference<ConverterTestDto>() {
            };

            //When/Then
            assertThrows(DataConversionException.class, () ->
                    jsonConverter.readValue(invalidJson, typeReference)
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
