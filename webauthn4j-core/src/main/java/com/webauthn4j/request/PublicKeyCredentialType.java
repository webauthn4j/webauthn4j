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

package com.webauthn4j.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;

/**
 * This enumeration defines the valid credential types. It is an extension point; values can be added to it
 * in the future, as more credential types are defined.
 * The values of this enumeration are used for versioning the Authentication Assertion and attestation structures
 * according to the type of the authenticator.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#credentialType">
 * §5.10.2. Credential Type Enumeration (enum PublicKeyCredentialType)</a>
 */
public enum PublicKeyCredentialType {

    PUBLIC_KEY("public-key");

    private String value;

    PublicKeyCredentialType(String value) {
        this.value = value;
    }

    public static PublicKeyCredentialType create(String value) {
        if (value == null) {
            return null;
        }
        if ("public-key".equals(value)) {
            return PUBLIC_KEY;
        } else {
            throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static PublicKeyCredentialType fromJson(String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, PublicKeyCredentialType.class);
        }
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
