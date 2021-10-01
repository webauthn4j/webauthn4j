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
 * This enumeration’s values describe authenticators' attachment modalities. Relying Parties use this for two purposes:
 * <ul>
 * <li>to express a preferred authenticator attachment modality when calling navigator.credentials.create()
 * to create a credential, and</li>
 * <li>to inform the client of the Relying Party's best belief about how to locate the managing authenticators of
 * the credentials listed in allowCredentials when calling navigator.credentials.get().</li>
 * </ul>
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#attachment">
 * §5.4.5. Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>
 */
public class AuthenticatorAttachment {

    /**
     * This value indicates platform attachment.
     */
    public static final AuthenticatorAttachment PLATFORM = new AuthenticatorAttachment("platform");

    /**
     * This value indicates cross-platform attachment.
     */
    public static final AuthenticatorAttachment CROSS_PLATFORM = new AuthenticatorAttachment("cross-platform");

    private final String value;

    private AuthenticatorAttachment(@NonNull String value) {
        this.value = value;
    }

    @JsonCreator
    public static @NonNull AuthenticatorAttachment create(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        switch (value) {
            case "platform":
                return PLATFORM;
            case "cross-platform":
                return CROSS_PLATFORM;
            default:
                return new AuthenticatorAttachment(value);
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
        AuthenticatorAttachment that = (AuthenticatorAttachment) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
