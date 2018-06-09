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

package com.webauthn4j.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum COSEKeyType {
    OKP(1), // https://tools.ietf.org/html/rfc8152#section-13
    EC2(2), // https://tools.ietf.org/html/rfc8152#section-13
    RSA(3), // https://tools.ietf.org/html/rfc8230#section-4
    SYMMETRIC(4), // https://tools.ietf.org/html/rfc8152#section-13
    RESERVED(0);  // https://tools.ietf.org/html/rfc8152#section-13

    private final int value;

    COSEKeyType(int value) {
        this.value = value;
    }

    @JsonCreator
    public static COSEKeyType create(int value) {
        switch (value) {
            case 1:
                return OKP;
            case 2:
                return EC2;
            case 3:
                return RSA;
            case 4:
                return SYMMETRIC;
            case 0:
                return RESERVED;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }
}
