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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class ResidentKeyRequirementTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(ResidentKeyRequirement.create(null)).isNull(),
                () -> assertThat(ResidentKeyRequirement.create("discouraged")).isEqualTo(ResidentKeyRequirement.DISCOURAGED),
                () -> assertThat(ResidentKeyRequirement.create("preferred")).isEqualTo(ResidentKeyRequirement.PREFERRED),
                () -> assertThat(ResidentKeyRequirement.create("required")).isEqualTo(ResidentKeyRequirement.REQUIRED)
        );
    }

    @Test
    void create_invalid_value_test() {
        assertThrows(IllegalArgumentException.class,
                () -> ResidentKeyRequirement.create("invalid")
        );
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
    void deserialize_test_with_invalid() {
        assertThrows(InvalidFormatException.class,
                () -> objectMapper.readValue("{\"residentKey\": \"invalid\"}", ResidentKeyRequirementTest.TestDTO.class)
        );
    }

    public static class TestDTO {
        public ResidentKeyRequirement residentKey;
    }


}