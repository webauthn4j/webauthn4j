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

package com.webauthn4j.util.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.Signature;

import java.util.Arrays;

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

    public static JWAIdentifier create(String value) {
        if (value == null) {
            return null;
        }

        return Arrays.stream(values())
                .filter(it -> it.name.equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("JWA Identifier '" + value + "' not supported"));
    }

    @JsonCreator
    private static JWAIdentifier fromJson(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, JWAIdentifier.class);
        }
    }

    @JsonValue
    public String getName() {
        return name;
    }

    public String getJcaName() {
        return jcaName;
    }

    public Signature.SignatureVerifierBuilder signatureVerifier() {
        return Signature.SignatureVerifierBuilder.forAlgorithm(this);
    }

    public Signature.SignatureBuilder signatureBuilder() {
        return Signature.SignatureBuilder.forAlgorithm(this);
    }
}
