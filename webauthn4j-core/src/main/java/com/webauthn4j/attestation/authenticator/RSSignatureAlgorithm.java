package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public class RSSignatureAlgorithm extends AbstractSignatureAlgorithm {

    public static final RSSignatureAlgorithm SHA256withRSA = new RSSignatureAlgorithm(-257, "SHA256withRSA");
    public static final RSSignatureAlgorithm SHA384withRSA = new RSSignatureAlgorithm(-258, "SHA384withRSA");
    public static final RSSignatureAlgorithm SHA512withRSA = new RSSignatureAlgorithm(-259, "SHA512withRSA");

    private RSSignatureAlgorithm(int value, String name) {
        super(value, name);
    }

    @JsonCreator
    public static RSSignatureAlgorithm create(int value) {
        switch (value) {
            case -257:
                return SHA256withRSA;
            case -258:
                return SHA384withRSA;
            case -259:
                return SHA512withRSA;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }

    @JsonValue
    @Override
    public int getValue() {
        return super.getValue();
    }

}
