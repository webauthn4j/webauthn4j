package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;

public class UserVerificationIndexClientExtensionOutput extends AbstractClientExtensionOutput<byte[]> {

    public static final String ID = "uvi";

    @JsonCreator
    public UserVerificationIndexClientExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
