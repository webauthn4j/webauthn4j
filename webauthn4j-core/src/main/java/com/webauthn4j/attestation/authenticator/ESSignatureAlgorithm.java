package com.webauthn4j.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public class ESSignatureAlgorithm extends AbstractSignatureAlgorithm {

    public static final ESSignatureAlgorithm SHA256withECDSA = new ESSignatureAlgorithm(-7, "SHA256withECDSA");
    public static final ESSignatureAlgorithm SHA384withECDSA = new ESSignatureAlgorithm(-35, "SHA384withECDSA");
    public static final ESSignatureAlgorithm SHA512withECDSA = new ESSignatureAlgorithm(-36, "SHA512withECDSA");

    private ESSignatureAlgorithm(int value, String name) {
        super(value, name);
    }

    @JsonValue
    @Override
    public int getValue(){
        return super.getValue();
    }

    @JsonCreator
    public static ESSignatureAlgorithm create(int value){
        switch (value){
            case -7:
                return SHA256withECDSA;
            case -35:
                return SHA384withECDSA;
            case -36:
                return SHA512withECDSA;
            default:
                throw new IllegalArgumentException("value is out of range");
        }
    }

}
