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

package com.webauthn4j.server;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Data transfer object that represents relying party server property for validators
 */
public class ServerProperty implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final List<Origin> origins;
    private final String rpId;
    private final Challenge challenge;
    private final byte[] tokenBindingId;

    // ~ Constructor
    // ========================================================================================================

    public ServerProperty(Origin origin, String rpId, Challenge challenge, byte[] tokenBindingId) {
        if(origin == null){
            this.origins = null;
        }
        else {
            this.origins = Collections.singletonList(origin);
        }
        this.rpId = rpId;
        this.challenge = challenge;
        this.tokenBindingId = tokenBindingId;
    }

    public ServerProperty(List<Origin> origins, String rpId, Challenge challenge, byte[] tokenBindingId) {
        this.origins = origins;
        this.rpId = rpId;
        this.challenge = challenge;
        this.tokenBindingId = tokenBindingId;
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * @deprecated
     * Returns the {@link Origin}
     *
     * @return the {@link Origin}
     */
    @Deprecated
    public Origin getOrigin() {
        if(origins == null || origins.isEmpty()){
            return null;
        }
        else {
            return origins.get(0);
        }
    }

    /**
     * Returns the {@link Origin} list
     *
     * @return the {@link Origin} list
     */
    public List<Origin> getOrigins() {
        return origins;
    }

    /**
     * Returns the rpId
     *
     * @return the rpId
     */
    public String getRpId() {
        return rpId;
    }

    /**
     * Returns the {@link Challenge}
     *
     * @return the {@link Challenge}
     */
    public Challenge getChallenge() {
        return challenge;
    }

    /**
     * Returns the tokenBindingId
     *
     * @return the tokenBindingId
     */
    public byte[] getTokenBindingId() {
        return tokenBindingId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerProperty that = (ServerProperty) o;
        return Objects.equals(origins, that.origins) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(challenge, that.challenge) &&
                Arrays.equals(tokenBindingId, that.tokenBindingId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(origins, rpId, challenge);
        result = 31 * result + Arrays.hashCode(tokenBindingId);
        return result;
    }
}
