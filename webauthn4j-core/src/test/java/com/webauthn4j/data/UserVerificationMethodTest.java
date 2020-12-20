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
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

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
                () -> assertThat(UserVerificationMethod.create(0x0001)).isEqualTo(UserVerificationMethod.PRESENCE),
                () -> assertThat(UserVerificationMethod.create(0x0002)).isEqualTo(UserVerificationMethod.FINGERPRINT),
                () -> assertThat(UserVerificationMethod.create(0x0004)).isEqualTo(UserVerificationMethod.PASSCODE),
                () -> assertThat(UserVerificationMethod.create(0x0008)).isEqualTo(UserVerificationMethod.VOICEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x0010)).isEqualTo(UserVerificationMethod.FACEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x0020)).isEqualTo(UserVerificationMethod.LOCATION),
                () -> assertThat(UserVerificationMethod.create(0x0040)).isEqualTo(UserVerificationMethod.EYEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x0080)).isEqualTo(UserVerificationMethod.PATTERN),
                () -> assertThat(UserVerificationMethod.create(0x0100)).isEqualTo(UserVerificationMethod.HANDPRINT),
                () -> assertThat(UserVerificationMethod.create(0x0200)).isEqualTo(UserVerificationMethod.NONE),
                () -> assertThat(UserVerificationMethod.create(0x0400)).isEqualTo(UserVerificationMethod.ALL)
        );
    }

    @Test
    void getValue_test() {
        assertThat(UserVerificationMethod.FINGERPRINT.getValue()).isEqualTo(0x0002);
    }

    @Test
    void deserialize_test() {
        UserVerificationMethodTest.TestDTO dto = jsonConverter.readValue("{\"userVerificationMethod\": 16}", UserVerificationMethodTest.TestDTO.class);
        assertThat(dto.userVerificationMethod).isEqualTo(UserVerificationMethod.FACEPRINT);
    }

    @Test
    void deserialize_test_with_out_of_range_value() {
        assertThatThrownBy(
                () -> jsonConverter.readValue("{\"userVerificationMethod\": \"-1\"}", UserVerificationMethodTest.TestDTO.class)
        ).isInstanceOf(DataConversionException.class);
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonConverter.readValue("{\"userVerificationMethod\": \"\"}", UserVerificationMethodTest.TestDTO.class)
        ).isInstanceOf(DataConversionException.class);
    }

    @Test
    void deserialize_test_with_null() {
        UserVerificationMethodTest.TestDTO data = jsonConverter.readValue("{\"userVerificationMethod\":null}", UserVerificationMethodTest.TestDTO.class);
        assertThat(data.userVerificationMethod).isNull();
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public UserVerificationMethod userVerificationMethod;
    }

}