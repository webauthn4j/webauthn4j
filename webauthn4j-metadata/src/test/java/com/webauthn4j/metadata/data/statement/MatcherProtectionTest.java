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

package com.webauthn4j.metadata.data.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MatcherProtectionTest {


    private JsonConverter jsonConverter = JsonConverter.INSTANCE;

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(MatcherProtection.create(0x0001)).isEqualTo(MatcherProtection.SOFTWARE),
                () -> assertThat(MatcherProtection.create(0x0002)).isEqualTo(MatcherProtection.TEE),
                () -> assertThat(MatcherProtection.create(0x0004)).isEqualTo(MatcherProtection.ON_CHIP)
        );
    }

    @Test
    void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> MatcherProtection.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)
        );
    }

    @Test
    void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> MatcherProtection.create(-1)
        );
    }

    @Test
    void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> MatcherProtection.create(0x2A1D)
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(MatcherProtection.SOFTWARE.getValue()).isEqualTo(0x0001),
                () -> assertThat(MatcherProtection.TEE.getValue()).isEqualTo(0x0002),
                () -> assertThat(MatcherProtection.ON_CHIP.getValue()).isEqualTo(0x0004)
        );
    }

    @Test
    void fromInt_test() {
        MatcherProtectionTest.TestDTO dto1 = jsonConverter.readValue("{\"matcher_protection\":1}", MatcherProtectionTest.TestDTO.class);
        MatcherProtectionTest.TestDTO dto2 = jsonConverter.readValue("{\"matcher_protection\":2}", MatcherProtectionTest.TestDTO.class);
        MatcherProtectionTest.TestDTO dto3 = jsonConverter.readValue("{\"matcher_protection\":4}", MatcherProtectionTest.TestDTO.class);

        assertAll(
                () -> assertThat(dto1.matcher_protection).isEqualTo(MatcherProtection.SOFTWARE),
                () -> assertThat(dto2.matcher_protection).isEqualTo(MatcherProtection.TEE),
                () -> assertThat(dto3.matcher_protection).isEqualTo(MatcherProtection.ON_CHIP)
        );
    }

    @Test
    void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"matcher_protection\":123}", MatcherProtectionTest.TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public MatcherProtection matcher_protection;
    }

}