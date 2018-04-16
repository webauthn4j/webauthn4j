package com.webauthn4j.test.authenticator.fido.u2f;

public class AuthenticationResponse {

    private byte userPresense;
    private byte[] counter;
    private byte[] signature;

    public AuthenticationResponse(byte userPresence, byte[] counter, byte[] signature) {
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
