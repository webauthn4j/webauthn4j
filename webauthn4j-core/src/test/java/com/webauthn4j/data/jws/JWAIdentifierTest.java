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

package com.webauthn4j.data.jws;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;


@SuppressWarnings("ConstantConditions")
class JWAIdentifierTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();


    @Test
    void create_test() {
        assertAll(
                () -> assertThat(JWAIdentifier.create("ES256")).isEqualTo(JWAIdentifier.ES256),
                () -> assertThat(JWAIdentifier.create("ES384")).isEqualTo(JWAIdentifier.ES384),
                () -> assertThat(JWAIdentifier.create("ES512")).isEqualTo(JWAIdentifier.ES512),
                () -> assertThat(JWAIdentifier.create("RS1")).isEqualTo(JWAIdentifier.RS1),
                () -> assertThat(JWAIdentifier.create("RS256")).isEqualTo(JWAIdentifier.RS256),
                () -> assertThat(JWAIdentifier.create("RS384")).isEqualTo(JWAIdentifier.RS384),
                () -> assertThat(JWAIdentifier.create("RS512")).isEqualTo(JWAIdentifier.RS512),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> JWAIdentifier.create("invalid")),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> JWAIdentifier.create(""))
        );
    }

    @Test
    void create_null_test() {
        assertThatThrownBy(() -> JWAIdentifier.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getName_test() {
        assertThat(JWAIdentifier.ES256.getName()).isEqualTo("ES256");
    }

    @Test
    void getJcaName_test() {
        assertThat(JWAIdentifier.ES256.getJcaName()).isEqualTo("SHA256withECDSA");
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"jwa_id\":\"ES256\"}", TestDTO.class);
        assertThat(dto.jwa_id).isEqualTo(JWAIdentifier.ES256);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"jwa_id\":\"ES521\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public JWAIdentifier jwa_id;
    }
}
