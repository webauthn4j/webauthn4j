package com.webauthn4j.client.challenge;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class DefaultChallengeTest {

    @Test
    public void hashCode_test() {
        Challenge challengeA = new DefaultChallenge();
        Challenge challengeB = new DefaultChallenge(challengeA.getValue());

        assertThat(challengeA.hashCode()).isEqualTo(challengeB.hashCode());
    }


}
