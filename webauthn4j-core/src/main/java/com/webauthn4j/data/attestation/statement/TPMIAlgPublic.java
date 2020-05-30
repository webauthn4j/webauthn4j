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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

public enum TPMIAlgPublic {
    TPM_ALG_ERROR(0),
    TPM_ALG_RSA(1),
    TPM_ALG_NULL(0x10),
    TPM_ALG_ECDSA(0x18);
    private final int value;

    TPMIAlgPublic(int value) {
        this.value = value;
    }

    public static TPMIAlgPublic create(int value) {
        if (value == TPM_ALG_ERROR.value) {
            return TPM_ALG_ERROR;
        } else if (value == TPM_ALG_RSA.value) {
            return TPM_ALG_RSA;
        } else if (value == TPM_ALG_NULL.value) {
            return TPM_ALG_NULL;
        } else if (value == TPM_ALG_ECDSA.value) {
            return TPM_ALG_ECDSA;
        } else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    @SuppressWarnings("squid:S3776")
    private static TPMIAlgPublic deserialize(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, TPMIAlgPublic.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

}
