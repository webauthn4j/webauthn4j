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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.ArrayUtil;

import java.util.Arrays;

public enum TPMISTAttest {
    TPM_ST_ATTEST_CERTIFY(new byte[]{(byte) 0x80, (byte) 0x17}),
    TPM_ST_ATTEST_QUOTE(new byte[]{(byte) 0x80, (byte) 0x18}),
    TPM_ST_ATTEST_SESSION_AUDIT(new byte[]{(byte) 0x80, (byte) 0x16}),
    TPM_ST_ATTEST_COMMAND_AUDIT(new byte[]{(byte) 0x80, (byte) 0x15}),
    TPM_ST_ATTEST_TIME(new byte[]{(byte) 0x80, (byte) 0x19}),
    TPM_ST_ATTEST_CREATION(new byte[]{(byte) 0x80, (byte) 0x1A}),
    TPM_ST_ATTEST_NV(new byte[]{(byte) 0x80, (byte) 0x14});

    private final byte[] value;

    TPMISTAttest(byte[] value) {
        this.value = value;
    }

    public static TPMISTAttest create(byte[] value) {
        if (Arrays.equals(value, TPM_ST_ATTEST_CERTIFY.value)) {
            return TPM_ST_ATTEST_CERTIFY;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_QUOTE.value)) {
            return TPM_ST_ATTEST_QUOTE;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_SESSION_AUDIT.value)) {
            return TPM_ST_ATTEST_SESSION_AUDIT;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_COMMAND_AUDIT.value)) {
            return TPM_ST_ATTEST_COMMAND_AUDIT;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_TIME.value)) {
            return TPM_ST_ATTEST_TIME;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_CREATION.value)) {
            return TPM_ST_ATTEST_CREATION;
        } else if (Arrays.equals(value, TPM_ST_ATTEST_NV.value)) {
            return TPM_ST_ATTEST_NV;
        } else {
            throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonCreator
    private static TPMISTAttest deserialize(byte[] value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, TPMISTAttest.class);
        }
    }

    @JsonValue
    public byte[] getValue() {
        return ArrayUtil.clone(value);
    }
}
