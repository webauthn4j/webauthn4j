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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMISTAttestTest {
    JsonConverter jsonConverter = JsonConverter.INSTANCE;

    @Test
    void create() {
        assertAll(
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x17})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_CERTIFY),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x18})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_QUOTE),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x16})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_SESSION_AUDIT),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x15})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_COMMAND_AUDIT),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x19})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_TIME),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x1A})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_CREATION),
                () -> assertThat(TPMISTAttest.create(new byte[]{(byte) 0x80, (byte) 0x14})).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_NV)
        );
    }

    @Test
    void create_with_invalid_value() {
        assertThrows(IllegalArgumentException.class,
                () -> TPMISTAttest.create(new byte[]{})
        );
    }

    @Test
    void fromString_test() {
        byte[] source = new byte[]{(byte) 0x80, (byte) 0x17};
        TestDTO dto = jsonConverter.readValue("{\"tpmi_st_attest\":\"" + Base64.getEncoder().encodeToString(source) + "\"}", TestDTO.class);
        assertThat(dto.tpmi_st_attest).isEqualTo(TPMISTAttest.TPM_ST_ATTEST_CERTIFY);
    }

    @Test
    void fromString_test_with_invalid_value() {
        byte[] source = new byte[]{(byte) 0xff, (byte) 0xaa};
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"tpmi_st_attest\":\"" + Base64.getEncoder().encodeToString(source) + "\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public TPMISTAttest tpmi_st_attest;
    }
}
