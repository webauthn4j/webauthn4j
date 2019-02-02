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

package com.webauthn4j.response.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.ECUtil;

import java.security.spec.ECParameterSpec;

public enum Curve {

    SECP256R1(1),
    SECP384R1(2),
    SECP521R1(3);

    private final int value;

    Curve(int value) {
        this.value = value;
    }

    public static Curve create(Integer value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case 1:
                return SECP256R1;
            case 2:
                return SECP384R1;
            case 3:
                return SECP521R1;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static Curve fromJson(Integer value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, Curve.class);
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

    public ECParameterSpec getECParameterSpec() {
        switch (this.value) {
            case 1:
                return ECUtil.P_256_SPEC;
            case 2:
                return ECUtil.P_384_SPEC;
            case 3:
                return ECUtil.P_521_SPEC;
            default:
                throw new IllegalStateException();
        }
    }
}
