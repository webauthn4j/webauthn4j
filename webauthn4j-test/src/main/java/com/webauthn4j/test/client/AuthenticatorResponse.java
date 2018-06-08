package com.webauthn4j.test.client;

public class AuthenticatorResponse {

    private byte[] clientDataJSON;
    private String clientExtensionsJSON;

    public AuthenticatorResponse(byte[] clientDataJSON, String clientExtensionsJSON) {
        this.clientDataJSON = clientDataJSON;
        this.clientExtensionsJSON = clientExtensionsJSON;
    }

    public AuthenticatorResponse(byte[] clientDataJSON) {
        this(clientDataJSON, null);
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }
}
