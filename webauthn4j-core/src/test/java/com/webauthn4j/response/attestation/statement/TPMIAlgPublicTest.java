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

public class TPMIAlgPublicTest {

    @Test
    public void create_test() throws InvalidFormatException {

        assertThat(TPMIAlgPublic.create(0x0)).isEqualTo(TPMIAlgPublic.TPM_ALG_ERROR);
        assertThat(TPMIAlgPublic.create(0x1)).isEqualTo(TPMIAlgPublic.TPM_ALG_RSA);
        assertThat(TPMIAlgPublic.create(0x10)).isEqualTo(TPMIAlgPublic.TPM_ALG_NULL);
        assertThat(TPMIAlgPublic.create(0x18)).isEqualTo(TPMIAlgPublic.TPM_ALG_ECDSA);
        assertThat(TPMIAlgPublic.create(0x1A)).isEqualTo(TPMIAlgPublic.TPM_ALG_ECDAA);
    }

    @Test(expected = InvalidFormatException.class)
    public void create_with_invalid_value_test() throws InvalidFormatException {

        TPMIAlgPublic.create(0x2);
    }
}