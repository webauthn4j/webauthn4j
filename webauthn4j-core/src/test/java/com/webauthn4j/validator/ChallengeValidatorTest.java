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

package com.webauthn4j.validator;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.BadChallengeException;
import com.webauthn4j.validator.exception.MissingChallengeException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;


/**
 * Test for ChallengeValidator
 */
@SuppressWarnings("ConstantConditions")
class ChallengeValidatorTest {

    private final Origin origin = Origin.create("https://example.com");
    private final String rpId = "example.com";

    private final ChallengeValidator target = new ChallengeValidator();

    @Test
    void validate_test1() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x00});

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challengeB, null);

        //When
        target.validate(collectedClientData, serverProperty);
    }

    @Test
    void validate_test_with_different_challenge() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x01});

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challengeB, null);

        //When
        assertThrows(BadChallengeException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }

    @Test
    void validate_test_without_saved_challenge() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = null;

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(origin, rpId, challengeB, null);

        //When
        assertThrows(MissingChallengeException.class,
                () -> target.validate(collectedClientData, serverProperty)
        );
    }
}
