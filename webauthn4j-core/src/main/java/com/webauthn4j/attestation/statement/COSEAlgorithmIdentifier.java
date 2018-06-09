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

public enum COSEAlgorithmIdentifier {
    RS256(-257, "SHA256withRSA"),
    RS384(-258, "SHA384withRSA"),
    RS512(-259, "SHA512withRSA"),
    ES256(-7, "SHA256withECDSA"),
    ES384(-35, "SHA384withECDSA"),
    ES512(-36, "SHA512withECDSA");

    private final long value;
    private final String name;

    COSEAlgorithmIdentifier(long value, String name) {
        this.value = value;
        this.name = name;
    }

    @JsonCreator
    public static COSEAlgorithmIdentifier create(int value) {
        switch (value) {
            case -257:
                return RS256;
            case -258:
                return RS384;
            case -259:
                return RS512;
            case -7:
                return ES256;
            case -35:
                return ES384;
            case -36:
                return ES512;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }


    @JsonValue
    public long getValue() {
        return value;
    }

    public String getName() {
        return name;
    }
}
