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
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Data transfer object that represents relying party server property for verifiers
 */
public class ServerProperty extends CoreServerProperty {

    // ~ Instance fields
    // ================================================================================================

    private final Set<Origin> origins;
    private final byte[] tokenBindingId;

    // ~ Constructor
    // ========================================================================================================

    /**
     * @param origin         origin
     * @param rpId           rpId
     * @param challenge      challenge
     * @param tokenBindingId tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. Use constructor without tokenBindingId
     */
    @Deprecated(forRemoval = false)
    public ServerProperty(@NotNull Origin origin, @NotNull String rpId, @Nullable Challenge challenge, @Nullable byte[] tokenBindingId) {
        super(rpId, challenge);
        AssertUtil.notNull(origin, "origin must not be null");
        this.origins = Collections.singleton(origin);
        this.tokenBindingId = tokenBindingId;
    }

    /**
     * @param origins        origins
     * @param rpId           rpId
     * @param challenge      challenge
     * @param tokenBindingId tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3. Use constructor without tokenBindingId
     */
    @Deprecated(forRemoval = false)
    public ServerProperty(@NotNull Set<Origin> origins, @NotNull String rpId, @Nullable Challenge challenge, @Nullable byte[] tokenBindingId) {
        super(rpId, challenge);
        AssertUtil.notNull(origins, "origins must not be null");
        this.origins = Collections.unmodifiableSet(origins);
        this.tokenBindingId = tokenBindingId;
    }

    /**
     * @param origin         origin
     * @param rpId           rpId
     * @param challenge      challenge
     */
    public ServerProperty(@NotNull Origin origin, @NotNull String rpId, @Nullable Challenge challenge) {
        this(origin, rpId, challenge, null);
    }

    /**
     * @param origins        origins
     * @param rpId           rpId
     * @param challenge      challenge
     */
    public ServerProperty(@NotNull Set<Origin> origins, @NotNull String rpId, @Nullable Challenge challenge) {
        this(origins, rpId, challenge, null);
    }

    // ~ Methods
    // ========================================================================================================

    public @NotNull Set<Origin> getOrigins() {
        return this.origins;
    }

    /**
     * Returns the tokenBindingId
     *
     * @return the tokenBindingId
     * @deprecated While Token Binding was present in Level 1 and Level 2 of WebAuthn, its use is not expected in Level 3.
     */
    @Deprecated(forRemoval = false)
    public @Nullable byte[] getTokenBindingId() {
        return tokenBindingId;
    }

    @Override
    public boolean equals(@Nullable Object o) {
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

    @Override
    public String toString() {
        return "ServerProperty{" +
                "rpId=" + getRpId() +
                ", challenge=" + getChallenge() +
                ", origins=" + origins +
                ", tokenBindingId=" + ArrayUtil.toHexString(tokenBindingId) +
                '}';
    }
}
