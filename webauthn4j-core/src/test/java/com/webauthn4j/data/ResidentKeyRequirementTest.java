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

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class ResidentKeyRequirementTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(ResidentKeyRequirement.create("discouraged")).isEqualTo(ResidentKeyRequirement.DISCOURAGED),
                () -> assertThat(ResidentKeyRequirement.create("preferred")).isEqualTo(ResidentKeyRequirement.PREFERRED),
                () -> assertThat(ResidentKeyRequirement.create("required")).isEqualTo(ResidentKeyRequirement.REQUIRED)
        );
    }

    @Test
    void create_with_null_value_test() {
        assertThatThrownBy(() -> ResidentKeyRequirement.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_unknown_value_test() {
        assertThatCode(
                () -> ResidentKeyRequirement.create("unknown")
        ).doesNotThrowAnyException();
    }

    @Test
    void getValue_test() {
        assertThat(ResidentKeyRequirement.REQUIRED.getValue()).isEqualTo("required");
    }

    @Test
    void deserialize_test() throws IOException {
        ResidentKeyRequirementTest.TestDTO dto = objectMapper.readValue("{\"residentKey\": \"required\"}", ResidentKeyRequirementTest.TestDTO.class);
        assertThat(dto.residentKey).isEqualTo(ResidentKeyRequirement.REQUIRED);
    }

    @Test
    void deserialize_test_with_unknown_value() {
        assertThatCode(
                () -> objectMapper.readValue("{\"residentKey\": \"unknown\"}", ResidentKeyRequirementTest.TestDTO.class)
        ).doesNotThrowAnyException();
    }

    public static class TestDTO {
        public ResidentKeyRequirement residentKey;
    }


    @Test
    void equals_hashCode_test(){
        assertThat(ResidentKeyRequirement.create("unknown")).isEqualTo(ResidentKeyRequirement.create("unknown"));
        assertThat(ResidentKeyRequirement.create("required")).isEqualTo(ResidentKeyRequirement.REQUIRED);
        assertThat(ResidentKeyRequirement.create("required")).hasSameHashCodeAs(ResidentKeyRequirement.REQUIRED);
    }

    @Test
    void toString_test(){
        assertThat(ResidentKeyRequirement.REQUIRED).asString().isEqualTo("required");
    }
}