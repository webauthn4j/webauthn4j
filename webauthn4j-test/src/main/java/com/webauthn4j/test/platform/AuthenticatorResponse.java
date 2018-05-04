package com.webauthn4j.test.platform;

public class AuthenticatorResponse {

    private byte[] clientDataJSON;

    public AuthenticatorResponse(byte[] clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
    }

}
