package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.exception.NotImplementedException;

public enum Curve {

    SECP256R1(1),
    SECP384R1(2),
    SECP521R1(3);

    private int value;

    Curve(int value) {
        this.value = value;
    }

    @JsonCreator
    public static Curve create(int value) {
        switch (value) {
            case 1:
                return SECP256R1;
            case 2:
                return SECP384R1;
            case 3:
                return SECP521R1;
            default:
                throw new NotImplementedException();
        }
    }

    @JsonValue
    public int getValue() {
        return value;
    }

    public String getName() {
        switch (this.value) {
            case 1:
                return "secp256r1";
            case 2:
                return "secp384r1";
            case 3:
                return "secp521r1";
            default:
                throw new NotImplementedException();
        }
    }
}
