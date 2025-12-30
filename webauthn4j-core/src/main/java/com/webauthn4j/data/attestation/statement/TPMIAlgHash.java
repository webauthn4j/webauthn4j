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
import org.jetbrains.annotations.NotNull;
import tools.jackson.databind.exc.InvalidFormatException;

public enum TPMIAlgHash {

    TPM_ALG_ERROR(0x00),
    TPM_ALG_SHA1(0x04),
    TPM_ALG_SHA256(0x0B),
    TPM_ALG_SHA384(0x0C),
    TPM_ALG_SHA512(0x0D),
    TPM_ALG_NULL(0x10);

    private final int value;

    TPMIAlgHash(int value) {
        this.value = value;
    }

    public static @NotNull TPMIAlgHash create(int value) {
        if (value == TPM_ALG_ERROR.value) {
            return TPM_ALG_ERROR;
        }
        else if (value == TPM_ALG_SHA1.value) {
            return TPM_ALG_SHA1;
        }
        else if (value == TPM_ALG_SHA256.value) {
            return TPM_ALG_SHA256;
        }
        else if (value == TPM_ALG_SHA384.value) {
            return TPM_ALG_SHA384;
        }
        else if (value == TPM_ALG_SHA512.value) {
            return TPM_ALG_SHA512;
        }
        else if (value == TPM_ALG_NULL.value) {
            return TPM_ALG_NULL;
        }
        else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    @SuppressWarnings("squid:S3776")
    private static @NotNull TPMIAlgHash deserialize(int value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, TPMIAlgHash.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

}
