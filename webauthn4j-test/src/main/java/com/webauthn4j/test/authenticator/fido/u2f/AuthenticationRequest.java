package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.util.Experimental;

@Experimental
public class AuthenticationRequest {

    private byte control;
    private byte[] challenge;
    private byte[] applicationParameter;
    private byte[] keyHandle;

    public AuthenticationRequest(byte control, byte[] challenge, byte[] applicationParameter, byte[] keyHandle){
        if(challenge.length != 32){throw new IllegalArgumentException("challenge must be 32 bytes");}
        if(applicationParameter.length != 32){throw new IllegalArgumentException("applicationParameter must be 32 bytes");}

        this.control = control;
        this.challenge = challenge;
        this.applicationParameter = applicationParameter;
        this.keyHandle = keyHandle;
    }

    public byte getControl(){
        return control;
    }

    public byte[] getChallenge() {
        return challenge;
    }

    public byte[] getApplicationParameter() {
        return applicationParameter;
    }

    public byte[] getKeyHandle() {
        return keyHandle;
    }

}
