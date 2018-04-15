package com.webauthn4j.test.token;

public class AuthenticateResponse {

    private byte userPresense;
    private byte[] counter;
    private byte[] signature;

    public AuthenticateResponse(byte userPresence, byte[] counter, byte[] signature) {
        if(counter.length != 4){throw new IllegalArgumentException("counter must be 4 bytes");}

        this.userPresense = userPresence;
        this.counter = counter;
        this.signature = signature;
    }

    public byte getUserPresense() {
        return userPresense;
    }

    public byte[] getCounter() {
        return counter;
    }

    public byte[] getSignature() {
        return signature;
    }
}
