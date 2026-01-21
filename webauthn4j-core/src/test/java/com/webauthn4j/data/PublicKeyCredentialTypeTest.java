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

package com.webauthn4j.data;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;


@SuppressWarnings("ConstantConditions")
class PublicKeyCredentialTypeTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void test() {
        TestDto testDto = objectMapper.readValue("{\"type\": \"public-key\"}", TestDto.class);
        assertThat(testDto.getType()).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY);
    }

    @Test
    void null_test() {
        TestDto testDto = objectMapper.readValue("{\"type\": null}", TestDto.class);
        assertThat(testDto.getType()).isNull();
    }

    @Test
    void create_test() {
        PublicKeyCredentialType value = PublicKeyCredentialType.create("public-key");
        assertThat(value).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY);
    }

    @Test
    void create_null_test() {
        assertThatThrownBy(() -> PublicKeyCredentialType.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknown_data_test() {
        assertThatCode(
                () -> objectMapper.readValue("{\"type\": \"unknown-data\"}", TestDto.class)
        ).doesNotThrowAnyException();
    }

    @Test
    void equals_hashCode_test(){
        assertThat(PublicKeyCredentialType.create("unknown")).isEqualTo(PublicKeyCredentialType.create("unknown"));
        assertThat(PublicKeyCredentialType.create("public-key")).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY);
        assertThat(PublicKeyCredentialType.create("public-key")).hasSameHashCodeAs(PublicKeyCredentialType.PUBLIC_KEY);
    }

    @Test
    void toString_test(){
        assertThat(PublicKeyCredentialType.PUBLIC_KEY).asString().isEqualTo("public-key");
    }
}
