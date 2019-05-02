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

class TPMGeneratedTest {

    JsonConverter jsonConverter = new JsonConverter();

    @Test
    void create() {
        assertAll(
                () -> assertThat(TPMGenerated.create(new byte[]{(byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47})).isEqualTo(TPMGenerated.TPM_GENERATED_VALUE),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> TPMGenerated.create(new byte[]{}))
        );
    }

    @Test
    void fromString_test() {
        byte[] source = new byte[]{(byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47};
        TestDTO dto = jsonConverter.readValue("{\"tpm_generated\":\"" + Base64.getEncoder().encodeToString(source) + "\"}", TestDTO.class);
        assertThat(dto.tpm_generated).isEqualTo(TPMGenerated.TPM_GENERATED_VALUE);
    }

    @Test
    void fromString_test_with_invalid_value() {
        byte[] source = new byte[]{(byte) 0xff, (byte) 0xaa, (byte) 0xff, (byte) 0xaa};
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"tpm_generated\":\"" + Base64.getEncoder().encodeToString(source) + "\"}", TestDTO.class)
        );
    }

    static class TestDTO {
        public TPMGenerated tpm_generated;
    }
}
