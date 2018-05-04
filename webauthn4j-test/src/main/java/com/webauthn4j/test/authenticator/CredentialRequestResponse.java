package com.webauthn4j.test.authenticator;

public class CredentialRequestResponse {

    private byte[] credentialId;
    private byte[] collectedClientDataBytes;
    private byte[] authenticatorDataBytes;
    private byte[] signature;
    private byte[] userHandle;

    public CredentialRequestResponse(byte[] credentialId, byte[] collectedClientDataBytes, byte[] authenticatorDataBytes, byte[] signature, byte[] userHandle) {
        this.credentialId = credentialId;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public byte[] getCollectedClientDataBytes() {
        return collectedClientDataBytes;
    }

    public byte[] getAuthenticatorDataBytes() {
        return authenticatorDataBytes;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }
}
