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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import org.junit.jupiter.api.Test;

import static com.webauthn4j.data.attestation.statement.TPMEccCurve.TPM_ECC_NIST_P192;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMEccCurveTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final JsonConverter jsonConverter = objectConverter.getJsonConverter();

    @Test
    void create_test() {
        assertAll(
                () -> assertThat(TPMEccCurve.create(0x0000)).isEqualTo(TPMEccCurve.TPM_ECC_NONE),
                () -> assertThat(TPMEccCurve.create(0x0001)).isEqualTo(TPM_ECC_NIST_P192),
                () -> assertThat(TPMEccCurve.create(0x0002)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P224),
                () -> assertThat(TPMEccCurve.create(0x0003)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P256),
                () -> assertThat(TPMEccCurve.create(0x0004)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P384),
                () -> assertThat(TPMEccCurve.create(0x0005)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P521),
                () -> assertThat(TPMEccCurve.create(0x0010)).isEqualTo(TPMEccCurve.TPM_ECC_BN_P256),
                () -> assertThat(TPMEccCurve.create(0x0011)).isEqualTo(TPMEccCurve.TPM_ECC_BN_P638),
                () -> assertThat(TPMEccCurve.create(0x0020)).isEqualTo(TPMEccCurve.TPM_ECC_SM2_P256)
        );
    }

    @Test
    void create_with_invalid_value_test() {
        //noinspection ResultOfMethodCallIgnored
        assertThatThrownBy(() -> TPMEccCurve.create(0xFFFF)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void getBytes_test() {
        assertThat(TPMEccCurve.TPM_ECC_NIST_P256.getBytes()).isEqualTo(new byte[]{0x00, 0x03});
    }

    @Test
    void getValue_test() {
        assertThat(TPMEccCurve.TPM_ECC_NIST_P256.getValue()).isEqualTo(3);
    }

    @SuppressWarnings("ConstantConditions")
    @Test
    void fromString_test() {
        TestDTO dto = jsonConverter.readValue("{\"tpm_ecc_curve\":3}", TestDTO.class);
        assertThat(dto.tpm_ecc_curve).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P256);
    }

    @Test
    void fromString_test_with_invalid_value() {
        assertThrows(DataConversionException.class,
                () -> jsonConverter.readValue("{\"tpm_ecc_curve\":-1}", TestDTO.class)
        );
    }

    @Test
    void getEllipticCurve() {
        assertAll(
                () -> assertThat(TPMEccCurve.TPM_ECC_NIST_P256.getEllipticCurve()).isEqualTo(ECUtil.P_256_SPEC.getCurve()),
                () -> assertThat(TPMEccCurve.TPM_ECC_NIST_P384.getEllipticCurve()).isEqualTo(ECUtil.P_384_SPEC.getCurve()),
                () -> assertThat(TPMEccCurve.TPM_ECC_NIST_P521.getEllipticCurve()).isEqualTo(ECUtil.P_521_SPEC.getCurve()),
                () -> assertThrows(NotImplementedException.class,
                        TPM_ECC_NIST_P192::getEllipticCurve
                )
        );
    }

    static class TestDTO {
        public TPMEccCurve tpm_ecc_curve;
    }
}
