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
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class TokenBindingStatusTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TokenBindingStatus.create("present")).isEqualTo(TokenBindingStatus.PRESENT),
                () -> assertThat(TokenBindingStatus.create("supported")).isEqualTo(TokenBindingStatus.SUPPORTED),
                () -> assertThat(TokenBindingStatus.create("not-supported")).isEqualTo(TokenBindingStatus.NOT_SUPPORTED)
        );
    }

    @Test
    void create_with_unknown_value_test() {
        assertThatCode(
                () -> TokenBindingStatus.create("unknown")
        ).doesNotThrowAnyException();
    }

    @Test
    void create_with_null_value_test() {
        assertThatThrownBy(() -> TokenBindingStatus.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonMapper.readValue("{\"status\":\"present\"}", TestDTO.class);
        assertThat(dto.status).isEqualTo(TokenBindingStatus.PRESENT);
    }

    @Test
    void fromString_test_with_unknown_value() {
        assertThatCode(
                () -> jsonMapper.readValue("{\"status\":\"unknown\"}", TestDTO.class)
        ).doesNotThrowAnyException();
    }

    static class TestDTO {
        public TokenBindingStatus status;
    }

    @Test
    void equals_hashCode_test(){
        assertThat(TokenBindingStatus.create("unknown")).isEqualTo(TokenBindingStatus.create("unknown"));
        assertThat(TokenBindingStatus.create("present")).isEqualTo(TokenBindingStatus.PRESENT);
        assertThat(TokenBindingStatus.create("present")).hasSameHashCodeAs(TokenBindingStatus.PRESENT);
    }

    @Test
    void toString_test(){
        assertThat(TokenBindingStatus.PRESENT).asString().isEqualTo("present");
    }
}
