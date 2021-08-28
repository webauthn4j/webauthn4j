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

package com.webauthn4j.data.jws;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

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

    JWAIdentifier(@NonNull String name, @NonNull String jcaName) {
        this.name = name;
        this.jcaName = jcaName;
    }

    public static @NonNull JWAIdentifier create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        return Arrays.stream(values())
                .filter(it -> it.name.equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid JWA Identifier provided: " + value));
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull JWAIdentifier deserialize(@NonNull String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "Invalid JWA Identifier provided", value, JWAIdentifier.class);
        }
    }

    @JsonValue
    public @NonNull String getName() {
        return name;
    }

    public @NonNull String getJcaName() {
        return jcaName;
    }

    @Override
    public String toString() {
        return name;
    }
}
