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
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.InvalidFormatException;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMIAlgPublicTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TPMIAlgPublic.create(0x0)).isEqualTo(TPMIAlgPublic.TPM_ALG_ERROR),
                () -> assertThat(TPMIAlgPublic.create(0x1)).isEqualTo(TPMIAlgPublic.TPM_ALG_RSA),
                () -> assertThat(TPMIAlgPublic.create(0x10)).isEqualTo(TPMIAlgPublic.TPM_ALG_NULL),
                () -> assertThat(TPMIAlgPublic.create(0x18)).isEqualTo(TPMIAlgPublic.TPM_ALG_ECDSA),
                () -> assertThat(TPMIAlgPublic.create(0x23)).isEqualTo(TPMIAlgPublic.TPM_ALG_ECC)
        );
    }

    @Test
    void create_with_invalid_value_test() {
        assertThatThrownBy(() -> TPMIAlgPublic.create(0x2)).isInstanceOf(IllegalArgumentException.class);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void fromString_test() {
        TestDTO dto = jsonMapper.readValue("{\"tpmi_alg_pub\":24}", TestDTO.class);
        assertThat(dto.tpmi_alg_pub).isEqualTo(TPMIAlgPublic.TPM_ALG_ECDSA);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(InvalidFormatException.class,
                () -> jsonMapper.readValue("{\"tpmi_alg_pub\":-1}", TestDTO.class)
        );
    }

    static class TestDTO {
        public TPMIAlgPublic tpmi_alg_pub;
    }
}
