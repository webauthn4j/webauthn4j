package com.webauthn4j.test.platform;

public class WebAuthnAuthenticationRequest {

    private String credentialId;
    private byte[] collectedClientData;
    private byte[] authenticatorData;
    private byte[] signature;

    public WebAuthnAuthenticationRequest(String credentialId, byte[] collectedClientData, byte[] authenticatorData, byte[] signature) {
        this.credentialId = credentialId;
        this.collectedClientData = collectedClientData;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }
}
