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
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Objects;

/**
 * {@link TokenBindingStatus} is one of the following:
 * <ul>
 * <li>supported</li>
 * <li>present</li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#enumdef-tokenbindingstatus">§5.10.1. Client Data Used in WebAuthn Signatures - TokenBindingStatus</a>
 */
public class TokenBindingStatus {

    /**
     * Indicates token binding was used when communicating with the Relying Party. In this case, the id member MUST be present.
     */
    public static final TokenBindingStatus PRESENT = new TokenBindingStatus("present");

    /**
     * Indicates the client supports token binding, but it was not negotiated when communicating with the Relying Party.
     */
    public static final TokenBindingStatus SUPPORTED = new TokenBindingStatus("supported");

    /**
     *
     */
    public static final TokenBindingStatus NOT_SUPPORTED = new TokenBindingStatus("not-supported");

    private final String value;

    private TokenBindingStatus(@NonNull String value) {
        this.value = value;
    }

    @JsonCreator
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
                return new TokenBindingStatus(value);
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenBindingStatus that = (TokenBindingStatus) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
