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

import com.webauthn4j.data.client.challenge.Challenge;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;
import java.util.Objects;

/**
 * The client data represents the contextual bindings of both the WebAuthn Relying Party and the client.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#sec-client-data">§5.10.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>
 */
public class CollectedClientData implements Serializable {

    //~ Instance fields ================================================================================================
    private ClientDataType type;
    private Challenge challenge;
    private Origin origin;
    private TokenBinding tokenBinding;

    public CollectedClientData(@Nullable ClientDataType type,
                               @Nullable Challenge challenge,
                               @Nullable Origin origin,
                               @Nullable TokenBinding tokenBinding) {
        this.type = type;
        this.challenge = challenge;
        this.origin = origin;
        this.tokenBinding = tokenBinding;
    }

    public CollectedClientData() {
    }

    public @Nullable ClientDataType getType() {
        return type;
    }

    public @Nullable Challenge getChallenge() {
        return challenge;
    }

    public @Nullable Origin getOrigin() {
        return origin;
    }

    public @Nullable TokenBinding getTokenBinding() {
        return tokenBinding;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CollectedClientData that = (CollectedClientData) o;
        return type == that.type &&
                Objects.equals(challenge, that.challenge) &&
                Objects.equals(origin, that.origin) &&
                Objects.equals(tokenBinding, that.tokenBinding);
    }

    @Override
    public int hashCode() {

        return Objects.hash(type, challenge, origin, tokenBinding);
    }
}
