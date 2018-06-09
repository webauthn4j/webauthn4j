package com.webauthn4j.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum COSEKeyOperation {
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

    private int value;

    COSEKeyOperation(int value) {
        this.value = value;
    }

    @JsonCreator
    public static COSEKeyOperation create(int value) {
        switch (value) {
            case 1:
                return COSEKeyOperation.SIGN;
            case 2:
                return COSEKeyOperation.VERIFY;
            case 3:
                return COSEKeyOperation.ENCRYPT;
            case 4:
                return COSEKeyOperation.DECRYPT;
            case 5:
                return COSEKeyOperation.WRAP_KEY;
            case 6:
                return COSEKeyOperation.UNWRAP_KEY;
            case 7:
                return COSEKeyOperation.DERIVE_KEY;
            case 8:
                return COSEKeyOperation.DERIVE_BITS;
            case 9:
                return COSEKeyOperation.MAC_CREATE;
            case 10:
                return COSEKeyOperation.MAC_VERIFY;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }
}
