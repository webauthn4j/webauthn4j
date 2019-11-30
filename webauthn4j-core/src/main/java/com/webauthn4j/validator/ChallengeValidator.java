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

package com.webauthn4j.validator;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.BadChallengeException;
import com.webauthn4j.validator.exception.MissingChallengeException;

import java.util.Arrays;

/**
 * Validates the specified {@link Challenge}
 */
class ChallengeValidator {

    //~ Instance fields
    // ================================================================================================


    // ~ Methods
    // ========================================================================================================

    void validate(RegistrationObject registrationObject,
                         CollectedClientData collectedClientData, ServerProperty serverProperty){
        validate(registrationObject, null, collectedClientData, serverProperty);
    }

    void validate(AuthenticationObject authenticationObject,
                  CollectedClientData collectedClientData, ServerProperty serverProperty){
        validate(null, authenticationObject, collectedClientData, serverProperty);
    }

    private void validate(RegistrationObject registrationObject, AuthenticationObject authenticationObject,
                         CollectedClientData collectedClientData, ServerProperty serverProperty) {
        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        Challenge savedChallenge = serverProperty.getChallenge();
        Challenge collectedChallenge = collectedClientData.getChallenge();

        if (savedChallenge == null) {
            throw new MissingChallengeException("The server doesn't have a challenge. The client must request the server to issue the challenge before WebAuthn operations.");
        }

        // Verify that the challenge member of the collectedClientData matches the challenge that was sent to
        // the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        validate(registrationObject, authenticationObject, savedChallenge, collectedChallenge);

    }

    private void validate(RegistrationObject registrationObject, AuthenticationObject authenticationObject,
                         Challenge expected, Challenge actual) {
        AssertUtil.notNull(expected, "expected must not be null");
        AssertUtil.notNull(actual, "actual must not be null");
        byte[] expectedChallengeBytes = expected.getValue();
        byte[] actualChallengeBytes = actual.getValue();

        if (!Arrays.equals(expectedChallengeBytes, actualChallengeBytes)) {
            throw new BadChallengeException("The actual challenge does not match the expected challenge", registrationObject, authenticationObject);
        }
    }
}
