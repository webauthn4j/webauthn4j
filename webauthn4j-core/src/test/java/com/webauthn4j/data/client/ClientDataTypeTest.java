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

package com.webauthn4j.data.client;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertAll;

class ClientDataTypeTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        //noinspection ConstantConditions,ResultOfMethodCallIgnored
        assertAll(
                () -> assertThat(ClientDataType.create("webauthn.create")).isEqualTo(ClientDataType.WEBAUTHN_CREATE),
                () -> assertThat(ClientDataType.create("webauthn.get")).isEqualTo(ClientDataType.WEBAUTHN_GET),
                () -> assertThat(ClientDataType.create(null)).isNull(),
                () -> assertThatCode(() -> ClientDataType.create("unknown")).doesNotThrowAnyException()
        );
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"client_data_type\":\"webauthn.create\"}", TestDTO.class);
        assertThat(dto.client_data_type).isEqualTo(ClientDataType.WEBAUTHN_CREATE);
    }

    @Test
    void fromString_test_with_unknown_value() {
        assertThatCode(
                () -> jsonConverter.readValue("{\"client_data_type\":\"unknown\"}", TestDTO.class)
        ).doesNotThrowAnyException();
    }

    static class TestDTO {
        public ClientDataType client_data_type;
    }

    @Test
    void equals_hashCode_test(){
        assertThat(ClientDataType.create("webauthn.create")).isEqualTo(ClientDataType.WEBAUTHN_CREATE);
        assertThat(ClientDataType.create("webauthn.create")).hasSameHashCodeAs(ClientDataType.WEBAUTHN_CREATE);
    }
}
