package com.webauthn4j.test.client;

public class AuthenticatorResponse {

    private byte[] clientDataJSON;
    private byte[] clientExtensions;

    public AuthenticatorResponse(byte[] clientDataJSON, byte[] clientExtensions) {
        this.clientDataJSON = clientDataJSON;
        this.clientExtensions = clientExtensions;
    }

    public AuthenticatorResponse(byte[] clientDataJSON) {
        this(clientDataJSON, null);
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

    public byte[] getClientExtensions() {
        return clientExtensions;
    }
}
