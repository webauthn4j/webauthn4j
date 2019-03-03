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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.ArrayUtil;

import java.util.Arrays;

public enum TPMGenerated {

    TPM_GENERATED_VALUE(new byte[]{(byte)0xff, (byte)0x54, (byte)0x43, (byte)0x47});

    private final byte[] value;

    TPMGenerated(byte[] value) {
        this.value = value;
    }

    public static TPMGenerated create(byte[] value) {
        if (Arrays.equals(value, TPM_GENERATED_VALUE.value)) {
            return TPM_GENERATED_VALUE;
        } else {
            throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonCreator
    private static TPMGenerated fromJson(byte[] value) throws InvalidFormatException {
        try{
            return create(value);
        }
        catch (IllegalArgumentException e){
            throw new InvalidFormatException(null, "value is out of range", value, TPMGenerated.class);
        }
    }

    @JsonValue
    public byte[] getValue() {
        return ArrayUtil.clone(value);
    }
}
