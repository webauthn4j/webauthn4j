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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.SignatureAlgorithm;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;


@SuppressWarnings("ConstantConditions")
class JWAIdentifierTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();


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
        TestDTO dto = jsonMapper.readValue("{\"jwa_id\":\"ES256\"}", TestDTO.class);
        assertThat(dto.jwa_id).isEqualTo(JWAIdentifier.ES256);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(InvalidFormatException.class,
                () -> jsonMapper.readValue("{\"jwa_id\":\"ES521\"}", TestDTO.class)
        );
    }

    @Test
    void toSignatureAlgorithm_test() {
        assertAll(
                () -> assertThat(JWAIdentifier.RS1.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS1),
                () -> assertThat(JWAIdentifier.RS256.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS256),
                () -> assertThat(JWAIdentifier.RS384.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS384),
                () -> assertThat(JWAIdentifier.RS512.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.RS512),
                () -> assertThat(JWAIdentifier.ES256.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.ES256),
                () -> assertThat(JWAIdentifier.ES384.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.ES384),
                () -> assertThat(JWAIdentifier.ES512.toSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.ES512)
        );
    }

    static class TestDTO {
        public JWAIdentifier jwa_id;
    }
}
