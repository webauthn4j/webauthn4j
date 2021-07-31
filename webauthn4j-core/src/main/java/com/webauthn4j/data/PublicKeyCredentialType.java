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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;

/**
 * {@link PublicKeyCredentialType} defines the valid credential types. It is an extension point;
 * values can be added to it in the future, as more credential types are defined.
 * The values of this enumeration are used for versioning the Authentication Assertion and attestation structures
 * according to the type of the authenticator.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#credentialType">
 * §5.10.2. Credential Type Enumeration (enum PublicKeyCredentialType)</a>
 */
@SuppressWarnings("SameReturnValue")
public enum PublicKeyCredentialType implements Serializable {

    PUBLIC_KEY("public-key");

    private final String value;

    PublicKeyCredentialType(String value) {
        this.value = value;
    }

    public static @NonNull PublicKeyCredentialType create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        if ("public-key".equals(value)) {
            return PUBLIC_KEY;
        }
        else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @SuppressWarnings("unused")
    @JsonCreator
    private static @NonNull PublicKeyCredentialType deserialize(@NonNull String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, PublicKeyCredentialType.class);
        }
    }

    @JsonValue
    public @NonNull String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }
}
