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
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

public class ClientDataType {
    public static final ClientDataType WEBAUTHN_CREATE = new ClientDataType("webauthn.create");
    public static final ClientDataType WEBAUTHN_GET = new ClientDataType("webauthn.get");
    /**
     * @deprecated ClientDataType.CREATE is renamed to ClientDataType.WEBAUTHN_CREATE
     */
    @Deprecated
    public static final ClientDataType CREATE = WEBAUTHN_CREATE;
    /**
     * @deprecated ClientDataType.GET is renamed to ClientDataType.WEBAUTHN_GET
     */
    @Deprecated
    public static final ClientDataType GET = WEBAUTHN_GET;

    private final String value;

    private ClientDataType(@NonNull String value) {
        this.value = value;
    }

    @SuppressWarnings("java:S1845")
    @JsonCreator
    public static @Nullable ClientDataType create(@Nullable String value) {
        if (value == null) {
            return null;
        }
        switch (value) {
            case "webauthn.create":
                return WEBAUTHN_CREATE;
            case "webauthn.get":
                return WEBAUTHN_GET;
            default:
                return new ClientDataType(value);
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
        ClientDataType that = (ClientDataType) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
