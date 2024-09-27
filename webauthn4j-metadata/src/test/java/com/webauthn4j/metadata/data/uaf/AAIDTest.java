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

package com.webauthn4j.metadata.data.uaf;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AAIDTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void constructor_test() {
        AAID aaid = new AAID("ABCD#1234");
        assertAll(
                () -> assertThat(aaid.getV()).isEqualTo(0xABCD),
                () -> assertThat(aaid.getM()).isEqualTo(0x1234)
        );
    }

    @Test
    void constructor_with_invalid_value_test() {
        assertThatThrownBy(() -> new AAID("1234##1234")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AAID("12341234")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AAID("123#1234")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AAID("1234#123")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_hashCode_test() {
        assertThat(new AAID("ABCD#1234")).isEqualTo(new AAID("ABCD#1234"));
        assertThat(new AAID("ABCD#1234")).hasSameHashCodeAs(new AAID("ABCD#1234"));
    }

    @Test
    void toString_test() {
        assertThat(new AAID("ABCD#1234").toString()).hasToString("ABCD#1234");
    }

    @Test
    void deserialize_with_invalid_value_test() {
        assertThatThrownBy(() -> objectConverter.getJsonConverter().readValue("{\"aaid\": \"invalid_value\"}", AAIDTest.TestDTO.class)).isInstanceOf(DataConversionException.class);
    }

    static class TestDTO {
        public AAID aaid;
    }

}