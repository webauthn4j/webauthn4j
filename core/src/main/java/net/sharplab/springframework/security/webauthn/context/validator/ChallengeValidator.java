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

package net.sharplab.springframework.security.webauthn.context.validator;

import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.exception.BadChallengeException;
import net.sharplab.springframework.security.webauthn.exception.MissingChallengeException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.util.Arrays;

/**
 * Validates {@link Challenge} instance
 */
public class ChallengeValidator {

    protected final Log logger = LogFactory.getLog(getClass());
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();


    public void validate(CollectedClientData collectedClientData, RelyingParty relyingParty) {
        Challenge savedChallenge = relyingParty.getChallenge();
        if (savedChallenge == null) {
            logger.debug("Authentication failed: challenge is not stored in the challenge repository");
            throw new MissingChallengeException(messages.getMessage(
                    "ChallengeValidator.missingChallenge",
                    "Missing challenge"));
        }
        byte[] savedChallengeValue = savedChallenge.getValue();

        byte[] challengeValueInClientData = collectedClientData.getChallenge().getValue();

        // Verify that the challenge member of the collectedClientData matches the challenge that was sent to
        // the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.
        if (!Arrays.equals(challengeValueInClientData, savedChallengeValue)) {
            logger.debug("Authentication failed: bad challenge is specified");
            throw new BadChallengeException(messages.getMessage(
                    "ChallengeValidator.badChallenge",
                    "Bad challenge"));
        }
    }
}
