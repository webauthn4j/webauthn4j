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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

@SuppressWarnings("ConstantConditions")
class UserVerificationRequirementTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(UserVerificationRequirement.create("discouraged")).isEqualTo(UserVerificationRequirement.DISCOURAGED),
                () -> assertThat(UserVerificationRequirement.create("preferred")).isEqualTo(UserVerificationRequirement.PREFERRED),
                () -> assertThat(UserVerificationRequirement.create("required")).isEqualTo(UserVerificationRequirement.REQUIRED)
        );
    }

    @Test
    void create_with_null_value_test() {
        assertThatThrownBy(() -> UserVerificationRequirement.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_unknown_value_test() {
        assertThatCode(
                () -> UserVerificationRequirement.create("unknown")
        ).doesNotThrowAnyException();
    }

    @Test
    void getValue() {
        assertThat(UserVerificationRequirement.REQUIRED.getValue()).isEqualTo("required");
    }

    @Test
    void fromString_test() throws IOException {
        TestDTO dto = objectMapper.readValue("{\"requirement\":\"required\"}", TestDTO.class);
        assertThat(dto.requirement).isEqualTo(UserVerificationRequirement.REQUIRED);
    }

    @Test
    void fromString_test_with_unknown_value() {
        assertThatCode(
                () -> objectMapper.readValue("{\"requirement\":\"unknown\"}", TestDTO.class)
        ).doesNotThrowAnyException();
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public UserVerificationRequirement requirement;
    }

    @Test
    void equals_hashCode_test(){
        assertThat(UserVerificationRequirement.create("required")).isEqualTo(UserVerificationRequirement.REQUIRED);
        assertThat(UserVerificationRequirement.create("required")).hasSameHashCodeAs(UserVerificationRequirement.REQUIRED);
    }

    @Test
    void toString_test(){
        assertThat(UserVerificationRequirement.REQUIRED).asString().isEqualTo("required");
    }
}
