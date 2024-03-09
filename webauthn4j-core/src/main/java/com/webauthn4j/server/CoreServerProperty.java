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

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

public class CoreServerProperty {

    private final String rpId;
    private final Challenge challenge;

    public CoreServerProperty(@NonNull String rpId, @Nullable Challenge challenge) {
        AssertUtil.notNull(rpId, "rpId must not be null");
        this.rpId = rpId;
        this.challenge = challenge;
    }

    /**
     * Returns the rpId
     *
     * @return the rpId
     */
    public @NonNull String getRpId() {
        return rpId;
    }

    /**
     * Returns the {@link Challenge}
     *
     * @return the {@link Challenge}
     */
    public @Nullable Challenge getChallenge() {
        return challenge;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreServerProperty that = (CoreServerProperty) o;
        return Objects.equals(rpId, that.rpId) &&
                Objects.equals(challenge, that.challenge);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rpId, challenge);
    }

    @Override
    public String toString() {
        return "CoreServerProperty(" +
                "rpId=" + rpId +
                ", challenge=" + challenge +
                ')';
    }
}
