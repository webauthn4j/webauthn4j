package com.webauthn4j.test.internal;

public class MLDSAKeyMaterial {

    private final byte[] seed;
    private final byte[] rawPublicKey;

    public MLDSAKeyMaterial(byte[] seed, byte[] rawPublicKey) {
        this.seed = seed;
        this.rawPublicKey = rawPublicKey;
    }

    public byte[] getSeed() {
        return seed;
    }

    public byte[] getRawPublicKey() {
        return rawPublicKey;
    }
}
