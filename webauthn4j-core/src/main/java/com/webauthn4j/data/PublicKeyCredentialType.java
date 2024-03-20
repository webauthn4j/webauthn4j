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
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Objects;

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
public class PublicKeyCredentialType {

    public static final PublicKeyCredentialType PUBLIC_KEY = new PublicKeyCredentialType("public-key");

    private final String value;

    private PublicKeyCredentialType(String value) {
        this.value = value;
    }

    @JsonCreator
    public static @NonNull PublicKeyCredentialType create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        if ("public-key".equals(value)) {
            return PUBLIC_KEY;
        }
        else {
            return new PublicKeyCredentialType(value);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialType that = (PublicKeyCredentialType) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
