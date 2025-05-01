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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

class AttestationConveyancePreferenceTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Nested
    class BasicOperations {
        
        @Test
        void getValue_test() {
            assertAll(
                    "All AttestationConveyancePreference values should return their correct respective values",
                    () -> assertThat(AttestationConveyancePreference.NONE.getValue()).isEqualTo("none"),
                    () -> assertThat(AttestationConveyancePreference.DIRECT.getValue()).isEqualTo("direct"),
                    () -> assertThat(AttestationConveyancePreference.INDIRECT.getValue()).isEqualTo("indirect"),
                    () -> assertThat(AttestationConveyancePreference.ENTERPRISE.getValue()).isEqualTo("enterprise")
            );
        }
        
        @Test
        void toString_test() {
            assertAll(
                    "All AttestationConveyancePreference values should convert to string correctly",
                    () -> assertThat(AttestationConveyancePreference.NONE).asString().isEqualTo("none"),
                    () -> assertThat(AttestationConveyancePreference.DIRECT).asString().isEqualTo("direct"),
                    () -> assertThat(AttestationConveyancePreference.INDIRECT).asString().isEqualTo("indirect"),
                    () -> assertThat(AttestationConveyancePreference.ENTERPRISE).asString().isEqualTo("enterprise")
            );
        }
        
        @Test
        void equals_hashCode_test() {
            assertAll(
                    () -> assertThat(AttestationConveyancePreference.create("unknown")).isEqualTo(AttestationConveyancePreference.create("unknown")),
                    () -> assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT),
                    () -> assertThat(AttestationConveyancePreference.create("direct")).hasSameHashCodeAs(AttestationConveyancePreference.DIRECT)
            );
        }
    }

    @Nested
    class CreateMethod {
        
        @Test
        void should_create_from_valid_values() {
            assertAll(
                    () -> assertThat(AttestationConveyancePreference.create("none")).isEqualTo(AttestationConveyancePreference.NONE),
                    () -> assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT),
                    () -> assertThat(AttestationConveyancePreference.create("indirect")).isEqualTo(AttestationConveyancePreference.INDIRECT),
                    () -> assertThat(AttestationConveyancePreference.create("enterprise")).isEqualTo(AttestationConveyancePreference.ENTERPRISE)
            );
        }

        @Test
        void should_throw_exception_with_null_value() {
            //noinspection ConstantConditions
            assertThatThrownBy(() -> AttestationConveyancePreference.create(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("value");
        }

        @Test
        void should_handle_unknown_value() {
            // According to the spec, unknown values should be processed without throwing an exception
            assertThatCode(() -> AttestationConveyancePreference.create("unknown"))
                    .doesNotThrowAnyException();
            
            // Verify that empty strings can also be handled
            assertThatCode(() -> AttestationConveyancePreference.create(""))
                    .doesNotThrowAnyException();
        }
    }

    @Nested
    class SerializationTests {
        
        @SuppressWarnings("ConstantConditions")
        @Test
        void should_deserialize_from_json() {
            TestDTO dto = jsonConverter.readValue("{\"preference\":\"none\"}", TestDTO.class);
            assertThat(dto.preference).isEqualTo(AttestationConveyancePreference.NONE);
        }

        @Test
        void should_handle_unknown_value_in_deserialization() {
            assertThatCode(() -> jsonConverter.readValue("{\"preference\":\"unknown\"}", TestDTO.class))
                    .doesNotThrowAnyException();
        }
        
        @Test
        void should_serialize_to_json() {
            TestDTO dto = new TestDTO();
            dto.preference = AttestationConveyancePreference.DIRECT;
            String json = jsonConverter.writeValueAsString(dto);
            assertThat(json).isEqualTo("{\"preference\":\"direct\"}");
        }
        
        @Test
        void should_deserialize_null_to_null() {
            TestDTO dto = jsonConverter.readValue("{\"preference\":null}", TestDTO.class);
            assertThat(dto.preference).isNull();
        }
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AttestationConveyancePreference preference;
    }
}