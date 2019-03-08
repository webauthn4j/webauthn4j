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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ResultOfMethodCallIgnored")
class UserVerificationMethodTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(UserVerificationMethod.create(0x00000001L)).isEqualTo(UserVerificationMethod.PRESENCE),
                () -> assertThat(UserVerificationMethod.create(0x00000002L)).isEqualTo(UserVerificationMethod.FINGERPRINT),
                () -> assertThat(UserVerificationMethod.create(0x00000004L)).isEqualTo(UserVerificationMethod.PASSCODE),
                () -> assertThat(UserVerificationMethod.create(0x00000008L)).isEqualTo(UserVerificationMethod.VOICEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x00000010L)).isEqualTo(UserVerificationMethod.FACEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x00000020L)).isEqualTo(UserVerificationMethod.LOCATION),
                () -> assertThat(UserVerificationMethod.create(0x00000040L)).isEqualTo(UserVerificationMethod.EYEPRINT),
                () -> assertThat(UserVerificationMethod.create(0x00000080L)).isEqualTo(UserVerificationMethod.PATTERN),
                () -> assertThat(UserVerificationMethod.create(0x00000100L)).isEqualTo(UserVerificationMethod.HANDPRINT),
                () -> assertThat(UserVerificationMethod.create(0x00000200L)).isEqualTo(UserVerificationMethod.NONE),
                () -> assertThat(UserVerificationMethod.create(0x00000400L)).isEqualTo(UserVerificationMethod.ALL),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> UserVerificationMethod.create(0xFFFFFFFFL))
        );
    }

    @Test
    void getValue_test() {
        assertThat(UserVerificationMethod.FINGERPRINT.getValue()).isEqualTo(0x00000002L);
    }

    @Test
    void fromLong_test() {
        TestDTO dto = jsonConverter.readValue("{\"user_verification_method\":64}", TestDTO.class);
        assertAll(
                () -> assertThat(dto.user_verification_method).isEqualTo(UserVerificationMethod.EYEPRINT),
                () -> assertThrows(DataConversionException.class,
                        () -> jsonConverter.readValue("{\"user_verification_method\":3}", TestDTO.class))
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public UserVerificationMethod user_verification_method;
    }
}
