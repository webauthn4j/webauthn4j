package com.webauthn4j.test.authenticator;

import com.webauthn4j.attestation.AttestationObject;

public class CredentialCreationResponse {

    private byte[] collectedClientData;
    private AttestationObject attestationObject;

    public CredentialCreationResponse(byte[] collectedClientData, AttestationObject attestationObject) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }
}
