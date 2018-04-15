package com.webauthn4j.test.platform;

public class WebAuthnRegistrationRequest {

    private byte[] collectedClientData;
    private byte[] attestationObject;

    public WebAuthnRegistrationRequest(byte[] collectedClientData,
                                       byte[] attestationObject) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

}
