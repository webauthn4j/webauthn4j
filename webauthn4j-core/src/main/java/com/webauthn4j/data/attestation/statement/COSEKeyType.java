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

import org.jetbrains.annotations.NotNull;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardDeserializer;
import com.webauthn4j.converter.jackson.ModuleNotRegisteredGuardSerializer;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using = ModuleNotRegisteredGuardSerializer.class)
@JsonDeserialize(using = ModuleNotRegisteredGuardDeserializer.class)
public enum COSEKeyType {
    OKP(1), // https://tools.ietf.org/html/rfc8152#section-13
    EC2(2), // https://tools.ietf.org/html/rfc8152#section-13
    RSA(3), // https://tools.ietf.org/html/rfc8230#section-4
    SYMMETRIC(4), // https://tools.ietf.org/html/rfc8152#section-13
    AKP(7), // https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
    RESERVED(0);  // https://tools.ietf.org/html/rfc8152#section-13

    private final int value;

    COSEKeyType(int value) {
        this.value = value;
    }

    public static @NotNull COSEKeyType create(int value) {
        switch (value) {
            case 1:
                return OKP;
            case 2:
                return EC2;
            case 3:
                return RSA;
            case 4:
                return SYMMETRIC;
            case 7:
                return AKP;
            case 0:
                return RESERVED;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    public int getValue() {
        return value;
    }
}
