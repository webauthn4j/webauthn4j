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

package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.ECUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.spec.ECParameterSpec;

public enum Curve {

    SECP256R1(1, 32, ECUtil.P_256_SPEC),
    SECP384R1(2, 48, ECUtil.P_384_SPEC),
    SECP521R1(3, 66, ECUtil.P_521_SPEC);

    private final int value;
    private final int size;
    private final ECParameterSpec parameterSpec;

    Curve(int value, int size, @NonNull ECParameterSpec parameterSpec) {
        this.value = value;
        this.size = size;
        this.parameterSpec = parameterSpec;
    }

    public static @NonNull Curve create(int value) {
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

    @SuppressWarnings({"SameParameterValue", "UnusedReturnValue"})
    @JsonCreator
    static @NonNull Curve deserialize(int value) throws InvalidFormatException {
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

    public int getSize() {
        return size;
    }

    public @NonNull ECParameterSpec getECParameterSpec() {
        return parameterSpec;
    }

    @Override
    public String toString() {
        switch (this){
            case SECP256R1:
                return "SECP256R1";
            case SECP384R1:
                return "SECP384R1";
            case SECP521R1:
                return "SECP521R1";
            default:
                return "Unknown Curve";
        }
    }

}
