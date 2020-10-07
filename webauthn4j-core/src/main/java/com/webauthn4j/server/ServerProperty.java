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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Data transfer object that represents relying party server property for validators
 */
public class ServerProperty extends CoreServerProperty {

    // ~ Instance fields
    // ================================================================================================

    private final Set<Origin> origins;
    private final byte[] tokenBindingId;

    // ~ Constructor
    // ========================================================================================================

    public ServerProperty(Origin origin, String rpId, Challenge challenge, byte[] tokenBindingId) {
        this(origin != null ? Collections.singleton(origin) : Collections.emptySet(),
                rpId,
                challenge, tokenBindingId);
    }

    public ServerProperty(Collection<Origin> origins, String rpId, Challenge challenge, byte[] tokenBindingId) {
        super(rpId, challenge);
        this.origins = (origins != null && !origins.isEmpty()) ? Collections.unmodifiableSet(new HashSet<>(origins)) : Collections.emptySet();
        this.tokenBindingId = tokenBindingId;
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * @deprecated
     * Returns a single {@link Origin}, provided that this ServerProperty is configured with only a single origin
     *
     * @return the {@link Origin}
     */
    @Deprecated
    public Origin getOrigin() {
        final int originsSize = origins.size();
        switch (originsSize){
            case 0:
                return null;
            case 1:
                return origins.iterator().next();
            default:
                throw new IllegalStateException("There are multiple Origins associated with this ServerProperty");
        }
    }

    public Set<Origin> getOrigins(){
        return this.origins;
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
        if (!super.equals(o)) return false;
        ServerProperty that = (ServerProperty) o;

        return Objects.equals(origins, that.origins) &&
                Arrays.equals(tokenBindingId, that.tokenBindingId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), origins);
        result = 31 * result + Arrays.hashCode(tokenBindingId);
        return result;
    }
}
