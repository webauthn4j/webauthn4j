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
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

public class DCServerProperty extends CoreServerProperty {

    /**
     * Constructor of {@link DCServerProperty}
     *
     * @param rpId      rpId or in other words, App ID, which is the concatenation of your 10-digit team identifier, a period, and your app’s CFBundleIdentifier value.
     * @param challenge challenge
     */
    public DCServerProperty(@NonNull String rpId, @Nullable Challenge challenge) {
        super(rpId, challenge);
    }

    /**
     * Constructor of {@link DCServerProperty}
     *
     * @param teamIdentifier     10-digit team identifier
     * @param cfBundleIdentifier CFBundleIdentifier
     * @param challenge          challenge
     */
    public DCServerProperty(@NonNull String teamIdentifier, @NonNull String cfBundleIdentifier, @Nullable Challenge challenge) {
        super(formatRpId(teamIdentifier, cfBundleIdentifier), challenge);
    }

    private static @NonNull String formatRpId(@NonNull String teamIdentifier, @NonNull String cfBundleIdentifier){
        AssertUtil.notNull(teamIdentifier, "teamIdentifier must not be null");
        AssertUtil.notNull(cfBundleIdentifier, "cfBundleIdentifier must not be null");
        return String.format("%s.%s", teamIdentifier, cfBundleIdentifier);
    }

}

