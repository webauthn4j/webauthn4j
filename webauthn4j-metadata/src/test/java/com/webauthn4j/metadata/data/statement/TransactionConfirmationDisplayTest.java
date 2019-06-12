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

class TransactionConfirmationDisplayTest {

    private JsonConverter jsonConverter = JsonConverter.INSTANCE;

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TransactionConfirmationDisplay.create(0x0001)).isEqualTo(TransactionConfirmationDisplay.ANY),
                () -> assertThat(TransactionConfirmationDisplay.create(0x0002)).isEqualTo(TransactionConfirmationDisplay.PRIVILEGED_SOFTWARE),
                () -> assertThat(TransactionConfirmationDisplay.create(0x0004)).isEqualTo(TransactionConfirmationDisplay.TEE),
                () -> assertThat(TransactionConfirmationDisplay.create(0x0008)).isEqualTo(TransactionConfirmationDisplay.HARDWARE),
                () -> assertThat(TransactionConfirmationDisplay.create(0x0010)).isEqualTo(TransactionConfirmationDisplay.REMOTE)
        );
    }

    @Test
    void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> TransactionConfirmationDisplay.create(UnsignedNumberUtil.UNSIGNED_SHORT_MAX + 1)
        );
    }

    @Test
    void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> TransactionConfirmationDisplay.create(-1)
        );
    }

    @Test
    void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> TransactionConfirmationDisplay.create(0x2A1D)
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(TransactionConfirmationDisplay.ANY.getValue()).isEqualTo(0x0001),
                () -> assertThat(TransactionConfirmationDisplay.PRIVILEGED_SOFTWARE.getValue()).isEqualTo(0x0002),
                () -> assertThat(TransactionConfirmationDisplay.TEE.getValue()).isEqualTo(0x0004),
                () -> assertThat(TransactionConfirmationDisplay.HARDWARE.getValue()).isEqualTo(0x0008),
                () -> assertThat(TransactionConfirmationDisplay.REMOTE.getValue()).isEqualTo(0x0010)
        );
    }

    @Test
    void fromInt_test() {
        TransactionConfirmationDisplayTest.TestDTO dto1 = jsonConverter.readValue("{\"transaction_confirmation_display\":1}", TransactionConfirmationDisplayTest.TestDTO.class);
        TransactionConfirmationDisplayTest.TestDTO dto2 = jsonConverter.readValue("{\"transaction_confirmation_display\":2}", TransactionConfirmationDisplayTest.TestDTO.class);
        TransactionConfirmationDisplayTest.TestDTO dto3 = jsonConverter.readValue("{\"transaction_confirmation_display\":4}", TransactionConfirmationDisplayTest.TestDTO.class);
        TransactionConfirmationDisplayTest.TestDTO dto4 = jsonConverter.readValue("{\"transaction_confirmation_display\":8}", TransactionConfirmationDisplayTest.TestDTO.class);
        TransactionConfirmationDisplayTest.TestDTO dto5 = jsonConverter.readValue("{\"transaction_confirmation_display\":16}", TransactionConfirmationDisplayTest.TestDTO.class);

        assertAll(
                () -> assertThat(dto1.transaction_confirmation_display).isEqualTo(TransactionConfirmationDisplay.ANY),
                () -> assertThat(dto2.transaction_confirmation_display).isEqualTo(TransactionConfirmationDisplay.PRIVILEGED_SOFTWARE),
                () -> assertThat(dto3.transaction_confirmation_display).isEqualTo(TransactionConfirmationDisplay.TEE),
                () -> assertThat(dto4.transaction_confirmation_display).isEqualTo(TransactionConfirmationDisplay.HARDWARE),
                () -> assertThat(dto5.transaction_confirmation_display).isEqualTo(TransactionConfirmationDisplay.REMOTE)
        );
    }

    @Test
    void fromInt_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"transaction_confirmation_display\":123}", TransactionConfirmationDisplayTest.TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public TransactionConfirmationDisplay transaction_confirmation_display;
    }


}