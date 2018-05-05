package com.webauthn4j.test.authenticator;

import com.webauthn4j.attestation.AttestationObject;

public class CredentialCreationResponse {

    private AttestationObject attestationObject;

    public CredentialCreationResponse(AttestationObject attestationObject) {
        this.attestationObject = attestationObject;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }
}
