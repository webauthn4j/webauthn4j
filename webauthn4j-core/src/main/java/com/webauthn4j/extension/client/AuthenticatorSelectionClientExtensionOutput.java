package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;

public class AuthenticatorSelectionClientExtensionOutput extends AbstractClientExtensionOutput<byte[][]> {

    public static final String ID = "authnSel";

    @JsonCreator
    public AuthenticatorSelectionClientExtensionOutput(byte[][] value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }
}
