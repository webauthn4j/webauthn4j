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

package com.webauthn4j.response.attestation.statement;

import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TPMEccCurveTest {

    @Test
    public void create_test() throws InvalidFormatException {
        assertThat(TPMEccCurve.create(0x0000)).isEqualTo(TPMEccCurve.TPM_ECC_NONE);
        assertThat(TPMEccCurve.create(0x0001)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P192);
        assertThat(TPMEccCurve.create(0x0002)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P224);
        assertThat(TPMEccCurve.create(0x0003)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P256);
        assertThat(TPMEccCurve.create(0x0004)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P384);
        assertThat(TPMEccCurve.create(0x0005)).isEqualTo(TPMEccCurve.TPM_ECC_NIST_P521);
        assertThat(TPMEccCurve.create(0x0010)).isEqualTo(TPMEccCurve.TPM_ECC_BN_P256);
        assertThat(TPMEccCurve.create(0x0011)).isEqualTo(TPMEccCurve.TPM_ECC_BN_P638);
        assertThat(TPMEccCurve.create(0x0020)).isEqualTo(TPMEccCurve.TPM_ECC_SM2_P256);
    }

    @Test(expected = InvalidFormatException.class)
    public void create_with_invalid_value_test() throws InvalidFormatException {
        TPMEccCurve.create(0xFFFF);
    }

    @Test
    public void getBytes_test() {
        assertThat(TPMEccCurve.TPM_ECC_NIST_P256.getBytes()).isEqualTo(new byte[]{0x00, 0x03});
    }

    @Test
    public void getValue_test() {
        assertThat(TPMEccCurve.TPM_ECC_NIST_P256.getValue()).isEqualTo(3);
    }

}
