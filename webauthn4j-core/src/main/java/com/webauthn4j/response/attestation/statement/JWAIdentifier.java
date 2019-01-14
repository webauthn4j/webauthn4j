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

public enum JWAIdentifier {
    RS1("RS1", "SHA1withRSA"),
    RS256("RS256", "SHA256withRSA"),
    RS384("RS384", "SHA384withRSA"),
    RS512("RS512", "SHA512withRSA"),
    ES256("ES256", "SHA256withECDSA"),
    ES384("ES384", "SHA384withECDSA"),
    ES512("ES512", "SHA512withECDSA");

    private final String name;
    private final String jcaName;

    JWAIdentifier(String name, String jcaName) {
        this.name = name;
        this.jcaName = jcaName;
    }

    @JsonCreator
    public static JWAIdentifier create(String value) throws InvalidFormatException {
        switch (value) {
            case "ES256":
                return ES256;
            case "ES384":
                return ES384;
            case "ES512":
                return ES512;
            case "RS1":
                return RS1;
            case "RS256":
                return RS256;
            case "RS384":
                return RS384;
            case "RS512":
                return RS512;
            default:
                throw new InvalidFormatException(null, "name is out of range", value, JWAIdentifier.class);
        }
    }


    @JsonValue
    public String getName() {
        return name;
    }

    public String getJcaName() {
        return jcaName;
    }
}
