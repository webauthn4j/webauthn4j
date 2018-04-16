package com.webauthn4j.test.platform;

import com.webauthn4j.client.challenge.Challenge;

public class PublicKeyCredentialCreationOptions {
    private Challenge challenge;

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }
}
