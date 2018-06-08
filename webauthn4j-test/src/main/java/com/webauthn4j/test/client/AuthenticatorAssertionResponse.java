package com.webauthn4j.test.client;

import com.webauthn4j.util.WIP;

@WIP
public class AuthenticatorAssertionResponse extends AuthenticatorResponse {

    private byte[] authenticatorData;
    private byte[] signature;
    private byte[] userHandle;

    public AuthenticatorAssertionResponse(byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, byte[] userHandle, String clientExtensionsJSON) {
        super(clientDataJSON, clientExtensionsJSON);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public AuthenticatorAssertionResponse(byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, byte[] userHandle) {
        super(clientDataJSON);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }
}
