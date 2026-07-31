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

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.json.JsonMapper;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VendorCommandIdTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constructor_test() {
        VendorCommandId id = new VendorCommandId(42L);
        assertThat(id.getValue()).isEqualTo(42L);
    }

    @Test
    void create_from_bigInteger_test() {
        VendorCommandId id = VendorCommandId.create(BigInteger.valueOf(42));
        assertThat(id.getValue()).isEqualTo(42L);
    }

    @Test
    void asBigInteger_test() {
        assertThat(new VendorCommandId(42).asBigInteger()).isEqualTo(BigInteger.valueOf(42));
    }

    @Test
    void asBigInteger_with_large_unsigned_value_test() {
        // -2 as long corresponds to 2^64 - 2 (UNSIGNED_LONG_MAX - 1) when interpreted as unsigned
        VendorCommandId id = new VendorCommandId(-2);
        assertThat(id.asBigInteger()).isEqualTo(new BigInteger("18446744073709551614"));
    }

    @Test
    void equals_hashCode_test() {
        VendorCommandId instanceA = new VendorCommandId(1L);
        VendorCommandId instanceB = new VendorCommandId(1L);
        VendorCommandId instanceC = new VendorCommandId(2L);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);

        assertThat(instanceA).isNotEqualTo(instanceC);
        assertThat(instanceA).isNotEqualTo(null);
        assertThat(instanceA).isNotEqualTo("string");
    }

    @Test
    void toString_test() {
        assertThat(new VendorCommandId(42)).hasToString("42");
    }

    @Test
    void toString_with_large_unsigned_value_test() {
        VendorCommandId id = new VendorCommandId(-2);
        assertThat(id).hasToString("18446744073709551614");
    }

    @Test
    void serialize_test() {
        TestDTO dto = new TestDTO();
        dto.commandId = new VendorCommandId(42);
        String json = jsonMapper.writeValueAsString(dto);
        assertThat(json).contains("\"commandId\":42");
    }

    @Test
    void serialize_test_with_large_unsigned_value() {
        TestDTO dto = new TestDTO();
        // -2 as long corresponds to 2^64 - 2 when interpreted as unsigned
        dto.commandId = new VendorCommandId(-2);
        String json = jsonMapper.writeValueAsString(dto);
        assertThat(json).contains("\"commandId\":18446744073709551614");
    }

    @Test
    void deserialize_test() {
        TestDTO dto = jsonMapper.readValue("{\"commandId\":42}", TestDTO.class);
        assertThat(dto.commandId).isEqualTo(new VendorCommandId(42));
    }

    @Test
    void deserialize_test_with_large_unsigned_value() {
        // 2^64 - 2 (UNSIGNED_LONG_MAX - 1)
        TestDTO dto = jsonMapper.readValue("{\"commandId\":18446744073709551614}", TestDTO.class);
        assertThat(dto.commandId.asBigInteger()).isEqualTo(new BigInteger("18446744073709551614"));
    }

    @Test
    void deserialize_test_with_invalid_value() {
        assertThatThrownBy(
                () -> jsonMapper.readValue("{\"commandId\":\"invalid\"}", TestDTO.class)
        ).isInstanceOf(MismatchedInputException.class);
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public VendorCommandId commandId;
    }
}
