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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMGeneratedTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void create() {
        assertAll(
                () -> assertThat(TPMGenerated.create(new byte[]{(byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47})).isEqualTo(TPMGenerated.TPM_GENERATED_VALUE),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> TPMGenerated.create(new byte[]{}))
        );
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void fromString_test() {
        byte[] source = new byte[]{(byte) 0xff, (byte) 0x54, (byte) 0x43, (byte) 0x47};
        TestDTO dto = jsonMapper.readValue("{\"tpm_generated\":\"" + Base64UrlUtil.encodeToString(source) + "\"}", TestDTO.class);
        assertThat(dto.tpm_generated).isEqualTo(TPMGenerated.TPM_GENERATED_VALUE);
    }

    @Test
    void fromString_test_with_invalid_value() {
        byte[] source = new byte[]{(byte) 0xff, (byte) 0xaa, (byte) 0xff, (byte) 0xaa};
        String sourceString = "{\"tpm_generated\":\"" + Base64UrlUtil.encodeToString(source) + "\"}";
        assertThrows(InvalidFormatException.class,
                () -> jsonMapper.readValue(sourceString, TestDTO.class)
        );
    }

    static class TestDTO {
        public TPMGenerated tpm_generated;
    }
}
