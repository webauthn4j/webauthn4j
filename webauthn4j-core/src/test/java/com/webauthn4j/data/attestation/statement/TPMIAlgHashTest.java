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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMIAlgHashTest {

    private ObjectConverter objectConverter = new ObjectConverter();
    private JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TPMIAlgHash.create(0x0)).isEqualTo(TPMIAlgHash.TPM_ALG_ERROR),
                () -> assertThat(TPMIAlgHash.create(0x04)).isEqualTo(TPMIAlgHash.TPM_ALG_SHA1),
                () -> assertThat(TPMIAlgHash.create(0x0B)).isEqualTo(TPMIAlgHash.TPM_ALG_SHA256),
                () -> assertThat(TPMIAlgHash.create(0x0C)).isEqualTo(TPMIAlgHash.TPM_ALG_SHA384),
                () -> assertThat(TPMIAlgHash.create(0x0D)).isEqualTo(TPMIAlgHash.TPM_ALG_SHA512),
                () -> assertThat(TPMIAlgHash.create(0x10)).isEqualTo(TPMIAlgHash.TPM_ALG_NULL)
        );
    }

    @Test
    void create_with_invalid_value_test() {
        assertThrows(IllegalArgumentException.class,
                () -> TPMIAlgHash.create(0x2)
        );
    }

    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"tpmi_alg_hash\":11}", TestDTO.class);
        assertThat(dto.tpmi_alg_hash).isEqualTo(TPMIAlgHash.TPM_ALG_SHA256);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"tpmi_alg_hash\":-1}", TestDTO.class)
        );
    }

    static class TestDTO {
        public TPMIAlgHash tpmi_alg_hash;
    }
}
