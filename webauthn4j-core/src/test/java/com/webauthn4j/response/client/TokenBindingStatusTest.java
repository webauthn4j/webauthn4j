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

package com.webauthn4j.response.client;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TokenBindingStatusTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TokenBindingStatus.create("present")).isEqualTo(TokenBindingStatus.PRESENT),
                () -> assertThat(TokenBindingStatus.create("supported")).isEqualTo(TokenBindingStatus.SUPPORTED),
                () -> assertThat(TokenBindingStatus.create("not-supported")).isEqualTo(TokenBindingStatus.NOT_SUPPORTED)
        );
    }

    @Test
    void create_with_illegal_value_test() {
        assertThrows(IllegalArgumentException.class,
                () -> TokenBindingStatus.create("illegal")
        );
    }

    @Test
    void create_with_null_value_test() throws IllegalArgumentException {
        assertThat(TokenBindingStatus.create(null)).isNull();
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"token_binding_id\":\"present\"}", TestDTO.class);
        assertThat(dto.token_binding_id).isEqualTo(TokenBindingStatus.PRESENT);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"token_binding_id\":\" not-supported\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public TokenBindingStatus token_binding_id;
    }
}
