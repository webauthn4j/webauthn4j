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
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * The client data represents the contextual bindings of both the WebAuthn Relying Party and the client.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#sec-client-data">§5.10.1. Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)</a>
 */
public class CollectedClientData {

    //~ Instance fields ================================================================================================
    private final ClientDataType type;
    private final Challenge challenge;
    private final Origin origin;
    private final Boolean crossOrigin;
    private final Origin topOrigin;
    private final TokenBinding tokenBinding;

    @JsonCreator
    public CollectedClientData(@NotNull @JsonProperty("type") ClientDataType type,
                               @NotNull @JsonProperty("challenge") Challenge challenge,
                               @NotNull @JsonProperty("origin") Origin origin,
                               @Nullable @JsonProperty("crossOrigin") Boolean crossOrigin,
                               @Nullable @JsonProperty("topOrigin") Origin topOrigin,
                               @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        AssertUtil.notNull(type, "type must not be null");
        AssertUtil.notNull(challenge, "challenge must not be null");
        AssertUtil.notNull(origin, "origin must not be null");
        this.type = type;
        this.challenge = challenge;
        this.origin = origin;
        this.crossOrigin = crossOrigin;
        this.topOrigin = topOrigin;
        this.tokenBinding = tokenBinding;
    }

    public CollectedClientData(@NotNull @JsonProperty("type") ClientDataType type,
                               @NotNull @JsonProperty("challenge") Challenge challenge,
                               @NotNull @JsonProperty("origin") Origin origin,
                               @Nullable @JsonProperty("crossOrigin") Boolean crossOrigin,
                               @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        this(type, challenge, origin, crossOrigin, null, tokenBinding);
    }

    public CollectedClientData(@NotNull @JsonProperty("type") ClientDataType type,
                               @NotNull @JsonProperty("challenge") Challenge challenge,
                               @NotNull @JsonProperty("origin") Origin origin,
                               @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        this(type, challenge, origin, null, tokenBinding);
    }


    public @NotNull ClientDataType getType() {
        return type;
    }

    public @NotNull Challenge getChallenge() {
        return challenge;
    }

    public @NotNull Origin getOrigin() {
        return origin;
    }

    public @NotNull Boolean getCrossOrigin() {
        return crossOrigin;
    }

    public @NotNull Origin getTopOrigin() {
        return topOrigin;
    }

    public @Nullable TokenBinding getTokenBinding() {
        return tokenBinding;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CollectedClientData that = (CollectedClientData) o;
        return Objects.equals(type, that.type) && Objects.equals(challenge, that.challenge) && Objects.equals(origin, that.origin) && Objects.equals(crossOrigin, that.crossOrigin) && Objects.equals(topOrigin, that.topOrigin) && Objects.equals(tokenBinding, that.tokenBinding);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, challenge, origin, crossOrigin, topOrigin, tokenBinding);
    }

    @Override
    public String toString() {
        return "CollectedClientData(" +
                "type=" + type +
                ", challenge=" + challenge +
                ", origin=" + origin +
                ", crossOrigin=" + crossOrigin +
                ", topOrigin=" + topOrigin +
                ", tokenBinding=" + tokenBinding +
                ')';
    }
}
