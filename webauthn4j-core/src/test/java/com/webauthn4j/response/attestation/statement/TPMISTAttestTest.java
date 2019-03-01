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
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TPMISTAttestTest {

    @Test
    public void create() {
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
    public void create_with_invalid_value() {
        assertThrows(InvalidFormatException.class,
                () -> TPMISTAttest.create(new byte[]{})
        );
    }
}