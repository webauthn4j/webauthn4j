/*
 * Copyright 2018 the original author or authors.
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
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.UnsignedNumberUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AttachmentHintTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(AttachmentHint.create(0x0001)).isEqualTo(AttachmentHint.INTERNAL),
                () -> assertThat(AttachmentHint.create(0x0002)).isEqualTo(AttachmentHint.EXTERNAL),
                () -> assertThat(AttachmentHint.create(0x0004)).isEqualTo(AttachmentHint.WIRED),
                () -> assertThat(AttachmentHint.create(0x0008)).isEqualTo(AttachmentHint.WIRELESS),
                () -> assertThat(AttachmentHint.create(0x0010)).isEqualTo(AttachmentHint.NFC),
                () -> assertThat(AttachmentHint.create(0x0020)).isEqualTo(AttachmentHint.BLUETOOTH),
                () -> assertThat(AttachmentHint.create(0x0040)).isEqualTo(AttachmentHint.NETWORK),
                () -> assertThat(AttachmentHint.create(0x0080)).isEqualTo(AttachmentHint.READY),
                () -> assertThat(AttachmentHint.create(0x0100)).isEqualTo(AttachmentHint.WIFI_DIRECT)
        );
    }

    @Test
    void create_test_with_value_over_upper_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> AttachmentHint.create(UnsignedNumberUtil.UNSIGNED_INT_MAX + 1)
        );
    }

    @Test
    void create_test_with_value_under_lower_bound() {
        assertThrows(IllegalArgumentException.class,
                () -> AttachmentHint.create(-1)
        );
    }

    @Test
    void create_test_with_out_of_range_value() {
        assertThrows(IllegalArgumentException.class,
                () -> AttachmentHint.create(0x2A1D)
        );
    }

    @Test
    void getValue_test() {
        assertAll(
                () -> assertThat(AttachmentHint.INTERNAL.getValue()).isEqualTo(0x0001),
                () -> assertThat(AttachmentHint.EXTERNAL.getValue()).isEqualTo(0x0002),
                () -> assertThat(AttachmentHint.WIRED.getValue()).isEqualTo(0x0004),
                () -> assertThat(AttachmentHint.WIRELESS.getValue()).isEqualTo(0x0008),
                () -> assertThat(AttachmentHint.NFC.getValue()).isEqualTo(0x0010),
                () -> assertThat(AttachmentHint.BLUETOOTH.getValue()).isEqualTo(0x0020),
                () -> assertThat(AttachmentHint.NETWORK.getValue()).isEqualTo(0x0040),
                () -> assertThat(AttachmentHint.READY.getValue()).isEqualTo(0x0080),
                () -> assertThat(AttachmentHint.WIFI_DIRECT.getValue()).isEqualTo(0x0100)
        );
    }

    @Test
    void fromInt_test() {
        AttachmentHintTest.TestDTO dto1 = jsonConverter.readValue("{\"attachment_hint\":1}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto2 = jsonConverter.readValue("{\"attachment_hint\":2}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto3 = jsonConverter.readValue("{\"attachment_hint\":4}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto4 = jsonConverter.readValue("{\"attachment_hint\":8}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto5 = jsonConverter.readValue("{\"attachment_hint\":16}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto6 = jsonConverter.readValue("{\"attachment_hint\":32}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto7 = jsonConverter.readValue("{\"attachment_hint\":64}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto8 = jsonConverter.readValue("{\"attachment_hint\":128}", AttachmentHintTest.TestDTO.class);
        AttachmentHintTest.TestDTO dto9 = jsonConverter.readValue("{\"attachment_hint\":256}", AttachmentHintTest.TestDTO.class);

        assertAll(
                () -> assertThat(dto1.attachment_hint).isEqualTo(AttachmentHint.INTERNAL),
                () -> assertThat(dto2.attachment_hint).isEqualTo(AttachmentHint.EXTERNAL),
                () -> assertThat(dto3.attachment_hint).isEqualTo(AttachmentHint.WIRED),
                () -> assertThat(dto4.attachment_hint).isEqualTo(AttachmentHint.WIRELESS),
                () -> assertThat(dto5.attachment_hint).isEqualTo(AttachmentHint.NFC),
                () -> assertThat(dto6.attachment_hint).isEqualTo(AttachmentHint.BLUETOOTH),
                () -> assertThat(dto7.attachment_hint).isEqualTo(AttachmentHint.NETWORK),
                () -> assertThat(dto8.attachment_hint).isEqualTo(AttachmentHint.READY),
                () -> assertThat(dto9.attachment_hint).isEqualTo(AttachmentHint.WIFI_DIRECT)
        );
    }

    @Test
    void fromLong_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"attachment_hint\":123}", AttachmentHintTest.TestDTO.class)
        );
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public AttachmentHint attachment_hint;
    }

}