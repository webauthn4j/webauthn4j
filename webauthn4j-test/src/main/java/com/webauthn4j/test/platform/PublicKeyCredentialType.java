package com.webauthn4j.test.platform;

import com.webauthn4j.util.Experimental;

@Experimental
public enum PublicKeyCredentialType {

    PublicKey("public-key");

    private String value;

    PublicKeyCredentialType(String value){
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
