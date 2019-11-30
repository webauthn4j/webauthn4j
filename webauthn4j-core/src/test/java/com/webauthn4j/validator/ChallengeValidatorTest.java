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

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.validator.exception.BadChallengeException;
import com.webauthn4j.validator.exception.MissingChallengeException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;


/**
 * Test for ChallengeValidator
 */
class ChallengeValidatorTest {

    private ChallengeValidator target = new ChallengeValidator();

    @Test
    void verifyChallenge_test1() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x00});

        RegistrationObject registrationObject = mock(RegistrationObject.class);
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(null, null, challengeB, null);

        //When
        target.validate(registrationObject, collectedClientData, serverProperty);
    }

    @Test
    void verifyChallenge_test_with_different_challenge() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = new DefaultChallenge(new byte[]{0x01});

        RegistrationObject registrationObject = mock(RegistrationObject.class);
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(null, null, challengeB, null);

        //When
        assertThrows(BadChallengeException.class,
                () -> target.validate(registrationObject, collectedClientData, serverProperty)
        );
    }

    @Test
    void verifyChallenge_test_without_saved_challenge() {

        Challenge challengeA = new DefaultChallenge(new byte[]{0x00});
        Challenge challengeB = null;

        RegistrationObject registrationObject = mock(RegistrationObject.class);
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, challengeA, null, null);
        ServerProperty serverProperty = new ServerProperty(null, null, challengeB, null);

        //When
        assertThrows(MissingChallengeException.class,
                () -> target.validate(registrationObject, collectedClientData, serverProperty)
        );
    }
}
