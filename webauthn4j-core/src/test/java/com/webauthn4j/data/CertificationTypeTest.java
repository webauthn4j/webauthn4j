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

package com.webauthn4j.data;

import com.webauthn4j.converter.util.ObjectConverter;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class CertificationTypeTest {

    private final JsonMapper jsonMapper = new ObjectConverter().getJsonMapper();

    @Test
    void constants_test() {
        assertAll(
                () -> assertThat(CertificationType.FIPS_CMVP_2.getValue()).isEqualTo("FIPS-CMVP-2"),
                () -> assertThat(CertificationType.FIPS_CMVP_3.getValue()).isEqualTo("FIPS-CMVP-3"),
                () -> assertThat(CertificationType.FIPS_CMVP_2_PHY.getValue()).isEqualTo("FIPS-CMVP-2-PHY"),
                () -> assertThat(CertificationType.FIPS_CMVP_3_PHY.getValue()).isEqualTo("FIPS-CMVP-3-PHY"),
                () -> assertThat(CertificationType.CC_EAL.getValue()).isEqualTo("CC-EAL"),
                () -> assertThat(CertificationType.FIDO.getValue()).isEqualTo("FIDO"),
                () -> assertThat(CertificationType.CCN_CPSTIC.getValue()).isEqualTo("CCN-CPSTIC")
        );
    }

    @Test
    void create_test() {
        CertificationType type = CertificationType.create("FIDO");
        assertThat(type).isEqualTo(CertificationType.FIDO);
    }

    @Test
    void create_unknown_value_test() {
        assertDoesNotThrow(() -> CertificationType.create("UNKNOWN"));
    }

    @Test
    void equals_hashCode_test() {
        CertificationType instanceA = CertificationType.create("FIDO");
        CertificationType instanceB = new CertificationType("FIDO");
        CertificationType instanceC = CertificationType.create("CC-EAL");

        assertThat(instanceA)
                .isEqualTo(CertificationType.FIDO)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);

        assertThat(instanceA).isNotEqualTo(instanceC);
        assertThat(instanceA).isNotEqualTo(null);
        assertThat(instanceA).isNotEqualTo("string");
    }

    @Test
    void toString_test() {
        assertThat(CertificationType.FIDO).hasToString("FIDO");
        assertThat(CertificationType.CC_EAL).hasToString("CC-EAL");
    }

    @Test
    void deserialize_map_test() {
        TestDTO dto = jsonMapper.readValue("""
                {"certifications": {"FIDO": 2, "FIPS-CMVP-2": 3, "CC-EAL": 5}}
                """, TestDTO.class);
        assertThat(dto.certifications)
                .containsEntry(CertificationType.FIDO, 2)
                .containsEntry(CertificationType.FIPS_CMVP_2, 3)
                .containsEntry(CertificationType.CC_EAL, 5)
                .hasSize(3);
    }

    @Test
    void deserialize_map_with_unknown_key_test() {
        TestDTO dto = jsonMapper.readValue("""
                {"certifications": {"UNKNOWN-CERT": 1}}
                """, TestDTO.class);
        assertThat(dto.certifications)
                .containsKey(new CertificationType("UNKNOWN-CERT"));
    }

    static class TestDTO {
        @SuppressWarnings("WeakerAccess")
        public Map<CertificationType, Integer> certifications;
    }
}
