package com.webauthn4j.test.platform;

import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;

public class PublicKeyCredentialParameters {

    private PublicKeyCredentialType type;
    private COSEAlgorithmIdentifier alg;

    public PublicKeyCredentialType getType() {
        return type;
    }

    public void setType(PublicKeyCredentialType type) {
        this.type = type;
    }

    public COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    public void setAlg(COSEAlgorithmIdentifier alg) {
        this.alg = alg;
    }



}
