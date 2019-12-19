/*
 * Copyright 2018 the original author or authors.
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

public class PublicKeyRepresentationFormatTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0100)).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0101)).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0102)).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_RAW),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0103)).isEqualTo(PublicKeyRepresentationFormat.RSA_2048_DER),
                () -> assertThat(PublicKeyRepresentationFormat.create(0x0104)).isEqualTo(PublicKeyRepresentationFormat.COSE),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> PublicKeyRepresentationFormat.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> PublicKeyRepresentationFormat.create(-1)),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> PublicKeyRepresentationFormat.create(0x0000))
        );
    }

    @Test
    void getValue_test() {
        assertThat(PublicKeyRepresentationFormat.ECC_X962_DER.getValue()).isEqualTo(0x0101);
    }

    @Test
    void fromInt_test() {
        TestDTO dto = jsonConverter.readValue("{\"pubkey_representation\":256}", TestDTO.class);
        assertAll(
                () -> assertThat(dto.pubkey_representation).isEqualTo(PublicKeyRepresentationFormat.ECC_X962_RAW),
                () -> assertThrows(DataConversionException.class,
                        () -> jsonConverter.readValue("{\"pubkey_representation\":1}", TestDTO.class))
        );
    }

    @Test
    void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"pubkey_representation\":1}", TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public PublicKeyRepresentationFormat pubkey_representation;
    }
}
