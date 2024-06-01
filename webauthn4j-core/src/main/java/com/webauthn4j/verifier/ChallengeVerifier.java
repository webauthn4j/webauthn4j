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

package com.webauthn4j.verifier;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.BadChallengeException;
import com.webauthn4j.verifier.exception.MissingChallengeException;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;

/**
 * Verifies the specified {@link Challenge}
 */
class ChallengeVerifier {

    //~ Instance fields
    // ================================================================================================


    // ~ Methods
    // ========================================================================================================
    public void verify(@NotNull CollectedClientData collectedClientData, @NotNull ServerProperty serverProperty) {
        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        Challenge savedChallenge = serverProperty.getChallenge();
        Challenge collectedChallenge = collectedClientData.getChallenge();

        if (savedChallenge == null) {
            throw new MissingChallengeException("The server doesn't have a challenge. The client must request the server to issue the challenge before WebAuthn operations.");
        }

        // Verify that the challenge member of the collectedClientData matches the challenge that was sent to
        // the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        verify(savedChallenge, collectedChallenge);
    }

    public void verify(@NotNull Challenge expected, @NotNull Challenge actual) {
        AssertUtil.notNull(expected, "expected must not be null");
        AssertUtil.notNull(actual, "actual must not be null");
        byte[] expectedChallengeBytes = expected.getValue();
        byte[] actualChallengeBytes = actual.getValue();

        if (!MessageDigest.isEqual(expectedChallengeBytes, actualChallengeBytes)) {
            throw new BadChallengeException("The actual challenge does not match the expected challenge");
        }
    }
}
