package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.exception.NotImplementedException;

import java.security.spec.ECParameterSpec;

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

    public ECParameterSpec getECParameterSpec() {
        switch (this.value) {
            case 1:
                return ECUtil.P_256_SPEC;
            case 2:
                return ECUtil.P_384_SPEC;
            case 3:
                return ECUtil.P_521_SPEC;
            default:
                throw new NotImplementedException();
        }
    }
}
