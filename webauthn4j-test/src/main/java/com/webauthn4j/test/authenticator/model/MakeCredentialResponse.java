package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.attestation.AttestationObject;

public class MakeCredentialResponse {

    private AttestationObject attestationObject;

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }
}
