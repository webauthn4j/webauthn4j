package com.webauthn4j.test.client;

public class AuthenticatorResponse {

    private byte[] clientDataJSON;

    public AuthenticatorResponse(byte[] clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

}
