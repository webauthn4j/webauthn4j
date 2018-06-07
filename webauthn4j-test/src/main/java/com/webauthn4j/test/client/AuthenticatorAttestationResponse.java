package com.webauthn4j.test.client;

import com.webauthn4j.util.WIP;

@WIP
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {

    private byte[] attestationObject;

    public AuthenticatorAttestationResponse(byte[] clientDataJSON,
                                            byte[] attestationObject,
                                            byte[] clientExtensions) {
        super(clientDataJSON, clientExtensions);
        this.attestationObject = attestationObject;
    }

    public AuthenticatorAttestationResponse(byte[] clientDataJSON,
                                            byte[] attestationObject) {
        super(clientDataJSON);
        this.attestationObject = attestationObject;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

}
