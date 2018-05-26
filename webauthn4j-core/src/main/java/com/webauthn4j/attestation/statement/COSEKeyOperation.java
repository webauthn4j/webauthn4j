package com.webauthn4j.attestation.statement;

public enum  COSEKeyOperation {
    SIGN(1),
    VERIFY(2),
    ENCRYPT(3),
    DECRYPT(4),
    WRAP_KEY(5),
    UNWRAP_KEY(6),
    DERIVE_KEY(7),
    DERIVE_BITS(8),
    MAC_CREATE(9),
    MAC_VERIFY(10);

    int value;

    COSEKeyOperation(int value){
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
