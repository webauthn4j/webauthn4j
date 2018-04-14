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

package com.webauthn4j.context.validator;

import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.context.RelyingParty;
import com.webauthn4j.exception.BadChallengeException;
import com.webauthn4j.exception.MissingChallengeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

/**
 * Validates {@link Challenge} instance
 */
public class ChallengeValidator {

    protected final Logger logger = LoggerFactory.getLogger(getClass());


    public void validate(CollectedClientData collectedClientData, RelyingParty relyingParty) {
        Challenge savedChallenge = relyingParty.getChallenge();
        if (savedChallenge == null) {
            logger.debug("Authentication failed: challenge is not stored in the challenge repository");
            throw new MissingChallengeException("Missing challenge");
        }
        byte[] savedChallengeValue = savedChallenge.getValue();

        byte[] challengeValueInClientData = collectedClientData.getChallenge().getValue();

        // Verify that the challenge member of the collectedClientData matches the challenge that was sent to
        // the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (!Arrays.equals(challengeValueInClientData, savedChallengeValue)) {
            logger.debug("Authentication failed: bad challenge is specified");
            throw new BadChallengeException("Bad challenge");
        }
    }
}
