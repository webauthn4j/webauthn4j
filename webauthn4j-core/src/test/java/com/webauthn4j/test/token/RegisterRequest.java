package com.webauthn4j.test.token;

public class RegisterRequest {

    private byte[] challengeParameter;
    private byte[] applicationParameter;

    public RegisterRequest(byte[] challengeParameter, byte[] applicationParameter){
        if(challengeParameter.length != 32){throw new IllegalArgumentException("challengeParameter must be 32 bytes");}
        if(applicationParameter.length != 32){throw new IllegalArgumentException("applicationParameter must be 32 bytes");}

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
