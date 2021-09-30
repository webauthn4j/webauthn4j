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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertAll;

class AttestationConveyancePreferenceTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.create("none")).isEqualTo(AttestationConveyancePreference.NONE),
                () -> assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT),
                () -> assertThat(AttestationConveyancePreference.create("indirect")).isEqualTo(AttestationConveyancePreference.INDIRECT),
                () -> assertThat(AttestationConveyancePreference.create("enterprise")).isEqualTo(AttestationConveyancePreference.ENTERPRISE)
        );
    }

    @Test
    void create_test_with_null_value() {
        //noinspection ConstantConditions
        assertThatThrownBy(() -> AttestationConveyancePreference.create(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void create_test_with_unknown_value() {
        assertThatCode(
                () -> AttestationConveyancePreference.create("unknown")
        ).doesNotThrowAnyException();
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(AttestationConveyancePreference.NONE.getValue()).isEqualTo("none"),
                () -> assertThat(AttestationConveyancePreference.DIRECT.getValue()).isEqualTo("direct"),
                () -> assertThat(AttestationConveyancePreference.INDIRECT.getValue()).isEqualTo("indirect"),
                () -> assertThat(AttestationConveyancePreference.ENTERPRISE.getValue()).isEqualTo("enterprise")
        );
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"preference\":\"none\"}", TestDTO.class);
        assertThat(dto.preference).isEqualTo(AttestationConveyancePreference.NONE);
    }

    @Test
    void fromString_test_with_unknown_value() {
        assertThatCode(
                () -> jsonConverter.readValue("{\"preference\":\"unknown\"}", TestDTO.class)
        ).doesNotThrowAnyException();
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AttestationConveyancePreference preference;
    }

    @Test
    void equals_hashCode_test(){
        assertThat(AttestationConveyancePreference.create("direct")).isEqualTo(AttestationConveyancePreference.DIRECT);
        assertThat(AttestationConveyancePreference.create("direct")).hasSameHashCodeAs(AttestationConveyancePreference.DIRECT);
    }

    @Test
    void toString_test(){
        assertThat(AttestationConveyancePreference.DIRECT).asString().isEqualTo("direct");
    }
}