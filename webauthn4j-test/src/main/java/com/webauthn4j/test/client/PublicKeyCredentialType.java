package com.webauthn4j.test.client;

import com.webauthn4j.util.WIP;

@WIP
public enum PublicKeyCredentialType {

    PublicKey("public-key");

    private String value;

    PublicKeyCredentialType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
