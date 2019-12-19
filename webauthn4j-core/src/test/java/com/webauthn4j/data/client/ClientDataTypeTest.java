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

package com.webauthn4j.data.client;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClientDataTypeTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(ClientDataType.create("webauthn.create")).isEqualTo(ClientDataType.CREATE),
                () -> assertThat(ClientDataType.create("webauthn.get")).isEqualTo(ClientDataType.GET),
                () -> assertThat(ClientDataType.create(null)).isNull(),
                //noinspection ResultOfMethodCallIgnored
                () -> assertThrows(IllegalArgumentException.class,
                        () -> ClientDataType.create("invalid")
                )
        );
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"client_data_type\":\"webauthn.create\"}", TestDTO.class);
        assertThat(dto.client_data_type).isEqualTo(ClientDataType.CREATE);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"client_data_type\":\"webauthn.get \"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public ClientDataType client_data_type;
    }
}
