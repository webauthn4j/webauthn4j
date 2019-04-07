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

package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Data transfer object that represents relying party server configuration for validators
 */
public class ServerProperty implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final Origin origin;
    private final String rpId;
    private final Challenge challenge;
    private final byte[] tokenBindingId;

    // ~ Constructor
    // ========================================================================================================

    public ServerProperty(Origin origin, String rpId, Challenge challenge, byte[] tokenBindingId) {
        this.origin = origin;
        this.rpId = rpId;
        this.challenge = challenge;
        this.tokenBindingId = tokenBindingId;
    }

    // ~ Methods
    // ========================================================================================================

    public Origin getOrigin() {
        return origin;
    }

    public String getRpId() {
        return rpId;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public byte[] getTokenBindingId() {
        return tokenBindingId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerProperty that = (ServerProperty) o;
        return Objects.equals(origin, that.origin) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(challenge, that.challenge) &&
                Arrays.equals(tokenBindingId, that.tokenBindingId);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(origin, rpId, challenge);
        result = 31 * result + Arrays.hashCode(tokenBindingId);
        return result;
    }
}
