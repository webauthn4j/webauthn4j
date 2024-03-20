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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * {@link TokenBinding} contains information about the state of the Token Binding protocol
 * used when communicating with the Relying Party. Its absence indicates that the client doesn’t
 * support token binding.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-tokenbinding">§5.10.1. Client Data Used in WebAuthn Signatures - tokenBinding</a>
 */
public class TokenBinding {

    @NonNull
    private final TokenBindingStatus status;
    @Nullable
    private final String id;

    @JsonCreator
    public TokenBinding(
            @NonNull @JsonProperty("status") TokenBindingStatus status,
            @Nullable @JsonProperty("id") String id) {
        AssertUtil.notNull(status, "status must not be null");
        this.status = status;
        this.id = id;
    }

    public TokenBinding(@NonNull TokenBindingStatus status, @Nullable byte[] id) {
        AssertUtil.notNull(status, "status must not be null");
        this.status = status;
        if (id == null) {
            this.id = null;
        }
        else {
            this.id = Base64UrlUtil.encodeToString(id);
        }
    }


    public @NonNull TokenBindingStatus getStatus() {
        return status;
    }

    public @Nullable String getId() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenBinding that = (TokenBinding) o;
        return status.equals(that.status) && Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {

        return Objects.hash(status, id);
    }

    @Override
    public String toString() {
        return "TokenBinding(" +
                "status=" + status +
                ", id=" + id +
                ')';
    }
}
