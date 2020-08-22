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
import java.util.Objects;

/**
 * Data transfer object that represents relying party server property for validators
 */
public class ServerProperty extends CoreServerProperty {

    // ~ Instance fields
    // ================================================================================================

    private final Origin origin;
    private final byte[] tokenBindingId;

    // ~ Constructor
    // ========================================================================================================

    public ServerProperty(Origin origin, String rpId, Challenge challenge, byte[] tokenBindingId) {
        super(rpId, challenge);
        this.origin = origin;
        this.tokenBindingId = tokenBindingId;
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * Returns the {@link Origin}
     *
     * @return the {@link Origin}
     */
    public Origin getOrigin() {
        return origin;
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
        return Objects.equals(origin, that.origin) &&
                Arrays.equals(tokenBindingId, that.tokenBindingId);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), origin);
        result = 31 * result + Arrays.hashCode(tokenBindingId);
        return result;
    }
}
