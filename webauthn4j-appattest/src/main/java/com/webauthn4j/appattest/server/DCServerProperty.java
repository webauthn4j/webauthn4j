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

package com.webauthn4j.appattest.server;

import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

public class DCServerProperty extends CoreServerProperty {

    private final byte[] clientDataHash;

    /**
     * Constructor of {@link DCServerProperty}
     *
     * @param rpId      rpId or in other words, App ID, which is the concatenation of your 10-digit team identifier, a period, and your app’s CFBundleIdentifier value.
     * @param challenge challenge
     */
    public DCServerProperty(@NotNull String rpId, @NotNull Challenge challenge) {
        super(rpId, challenge);
        AssertUtil.notNull(challenge, "challenge must not be null");
        this.clientDataHash = MessageDigestUtil.createSHA256().digest(challenge.getValue());
    }

    /**
     * Constructor of {@link DCServerProperty}
     *
     * @param teamIdentifier     10-digit team identifier
     * @param cfBundleIdentifier CFBundleIdentifier
     * @param challenge          challenge
     */
    public DCServerProperty(@NotNull String teamIdentifier, @NotNull String cfBundleIdentifier, @NotNull Challenge challenge) {
        this(formatRpId(teamIdentifier, cfBundleIdentifier), challenge);
    }

    /**
     * @param rpId expected App ID
     * @param clientDataHash expected SHA-256 hash computed by the server from validated data;
     *                       the caller must verify the embedded challenge before construction
     */
    public DCServerProperty(@NotNull String rpId, @NotNull byte[] clientDataHash) {
        super(rpId, null);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
    }

    /**
     * @param teamIdentifier team identifier
     * @param cfBundleIdentifier bundle identifier
     * @param clientDataHash expected SHA-256 hash computed by the server from validated data
     * @see #DCServerProperty(String, byte[])
     */
    public DCServerProperty(@NotNull String teamIdentifier, @NotNull String cfBundleIdentifier,
                            @NotNull byte[] clientDataHash) {
        this(formatRpId(teamIdentifier, cfBundleIdentifier), clientDataHash);
    }

    public @Nullable byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        DCServerProperty that = (DCServerProperty) o;
        return Arrays.equals(clientDataHash, that.clientDataHash);
    }

    @Override
    public int hashCode() {
        return 31 * super.hashCode() + Arrays.hashCode(clientDataHash);
    }

    private static @NotNull String formatRpId(@NotNull String teamIdentifier, @NotNull String cfBundleIdentifier) {
        AssertUtil.notNull(teamIdentifier, "teamIdentifier must not be null");
        AssertUtil.notNull(cfBundleIdentifier, "cfBundleIdentifier must not be null");
        return String.format("%s.%s", teamIdentifier, cfBundleIdentifier);
    }

}

