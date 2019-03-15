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

package com.webauthn4j.data.client;

import com.webauthn4j.data.client.challenge.Challenge;

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

    public CollectedClientData(ClientDataType type,
                               Challenge challenge,
                               Origin origin,
                               TokenBinding tokenBinding) {
        this.type = type;
        this.challenge = challenge;
        this.origin = origin;
        this.tokenBinding = tokenBinding;
    }

    public CollectedClientData() {
    }

    public ClientDataType getType() {
        return type;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public Origin getOrigin() {
        return origin;
    }

    public TokenBinding getTokenBinding() {
        return tokenBinding;
    }

    @Override
    public boolean equals(Object o) {
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
