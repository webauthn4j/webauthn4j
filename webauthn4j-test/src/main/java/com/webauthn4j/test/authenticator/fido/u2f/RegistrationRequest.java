package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.util.WIP;

@WIP
public class RegistrationRequest {

    private byte[] challengeParameter;
    private byte[] applicationParameter;

    public RegistrationRequest(byte[] challengeParameter, byte[] applicationParameter) {
        if (challengeParameter.length != 32) {
            throw new IllegalArgumentException("challengeParameter must be 32 bytes");
        }
        if (applicationParameter.length != 32) {
            throw new IllegalArgumentException("applicationParameter must be 32 bytes");
        }

        this.challengeParameter = challengeParameter;
        this.applicationParameter = applicationParameter;
    }

    public byte[] getChallengeParameter() {
        return challengeParameter;
    }

    public byte[] getApplicationParameter() {
        return applicationParameter;
    }
}
