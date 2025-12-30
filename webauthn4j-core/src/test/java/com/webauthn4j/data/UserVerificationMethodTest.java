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
import com.webauthn4j.converter.jackson.deserializer.json.UserVerificationMethodFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.UserVerificationMethodToStringSerializer;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class UserVerificationMethodTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(UserVerificationMethod.create(0x0001)).isEqualTo(UserVerificationMethod.PRESENCE_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0002)).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0004)).isEqualTo(UserVerificationMethod.PASSCODE_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0008)).isEqualTo(UserVerificationMethod.VOICEPRINT_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0010)).isEqualTo(UserVerificationMethod.FACEPRINT_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0020)).isEqualTo(UserVerificationMethod.LOCATION_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0040)).isEqualTo(UserVerificationMethod.EYEPRINT_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0080)).isEqualTo(UserVerificationMethod.PATTERN_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0100)).isEqualTo(UserVerificationMethod.HANDPRINT_INTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0800)).isEqualTo(UserVerificationMethod.PASSCODE_EXTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x1000)).isEqualTo(UserVerificationMethod.PATTERN_EXTERNAL),
                () -> assertThat(UserVerificationMethod.create(0x0200)).isEqualTo(UserVerificationMethod.NONE),
                () -> assertThat(UserVerificationMethod.create(0x0400)).isEqualTo(UserVerificationMethod.ALL)
        );
    }

    @Test
    void getValue_test() {
        assertThat(UserVerificationMethod.FINGERPRINT_INTERNAL.getValue()).isEqualTo(0x0002);
    }

    @Test
    void toString_test() {
        assertThat(UserVerificationMethod.FINGERPRINT_INTERNAL).hasToString("fingerprint_internal");
    }

    @Nested
    class IntSerialization {

        @Test
        void serialize_test(){
            UserVerificationMethodTest.IntSerializationTestDTO dto = new UserVerificationMethodTest.IntSerializationTestDTO();
            dto.userVerificationMethod = UserVerificationMethod.FINGERPRINT_INTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"userVerificationMethod\":2}");
        }

        @Test
        void deserialize_test() {
            UserVerificationMethodTest.IntSerializationTestDTO dto = jsonConverter.readValue("{\"userVerificationMethod\":2}", UserVerificationMethodTest.IntSerializationTestDTO.class);
            assertThat(dto.userVerificationMethod).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL);
        }

        @Test
        void deserialize_test_with_out_of_range_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"userVerificationMethod\": \"-1\"}", UserVerificationMethodTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"userVerificationMethod\": \"\"}", UserVerificationMethodTest.IntSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            UserVerificationMethodTest.IntSerializationTestDTO data = jsonConverter.readValue("{\"userVerificationMethod\":null}", UserVerificationMethodTest.IntSerializationTestDTO.class);
            assertThat(data.userVerificationMethod).isNull();
        }
    }

    static class IntSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        public UserVerificationMethod userVerificationMethod;
    }

    @Nested
    class StringSerialization {

        @Test
        void serialize_test(){
            UserVerificationMethodTest.StringSerializationTestDTO dto = new UserVerificationMethodTest.StringSerializationTestDTO();
            dto.userVerificationMethod = UserVerificationMethod.FINGERPRINT_INTERNAL;
            String string = jsonConverter.writeValueAsString(dto);
            assertThat(string).isEqualTo("{\"userVerificationMethod\":\"fingerprint_internal\"}");
        }

        @Test
        void deserialize_test() {
            UserVerificationMethodTest.StringSerializationTestDTO dto = jsonConverter.readValue("{\"userVerificationMethod\":\"fingerprint_internal\"}", UserVerificationMethodTest.StringSerializationTestDTO.class);
            assertThat(dto.userVerificationMethod).isEqualTo(UserVerificationMethod.FINGERPRINT_INTERNAL);
        }

        @Test
        void deserialize_test_with_invalid_value() {
            assertThatThrownBy(
                    () -> jsonConverter.readValue("{\"userVerificationMethod\": \"\"}", UserVerificationMethodTest.StringSerializationTestDTO.class)
            ).isInstanceOf(DataConversionException.class);
        }

        @Test
        void deserialize_test_with_null() {
            UserVerificationMethodTest.StringSerializationTestDTO data = jsonConverter.readValue("{\"userVerificationMethod\":null}", UserVerificationMethodTest.StringSerializationTestDTO.class);
            assertThat(data.userVerificationMethod).isNull();
        }
    }

    static class StringSerializationTestDTO {
        @SuppressWarnings("WeakerAccess")
        @JsonSerialize(using = UserVerificationMethodToStringSerializer.class)
        @JsonDeserialize(using = UserVerificationMethodFromStringDeserializer.class)
        public UserVerificationMethod userVerificationMethod;
    }

}