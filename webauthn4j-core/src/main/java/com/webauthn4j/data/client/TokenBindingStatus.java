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

package com.webauthn4j.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

/**
 * {@link TokenBindingStatus} is one of the following:
 * <ul>
 * <li>supported</li>
 * <li>present</li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#enumdef-tokenbindingstatus">§5.10.1. Client Data Used in WebAuthn Signatures - TokenBindingStatus</a>
 */
public enum TokenBindingStatus {

    /**
     * Indicates token binding was used when communicating with the Relying Party. In this case, the id member MUST be present.
     */
    PRESENT("present"),

    /**
     * Indicates the client supports token binding, but it was not negotiated when communicating with the Relying Party.
     */
    SUPPORTED("supported"),

    /**
     *
     */
    NOT_SUPPORTED("not-supported");

    private final String value;

    TokenBindingStatus(@NonNull String value) {
        this.value = value;
    }

    public static @NonNull TokenBindingStatus create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        switch (value) {
            case "present":
                return PRESENT;
            case "supported":
                return SUPPORTED;
            case "not-supported":
                return NOT_SUPPORTED;
            default:
                throw new IllegalArgumentException("value '" + value + "' is out of range");
        }
    }

    @JsonCreator
    private static @NonNull TokenBindingStatus deserialize(@NonNull String value) throws InvalidFormatException {
        try {
            return create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, TokenBindingStatus.class);
        }
    }

    @JsonValue
    public @NonNull String getValue() {
        return this.value;
    }

    @Override
    public String toString() {
        return value;
    }
}
