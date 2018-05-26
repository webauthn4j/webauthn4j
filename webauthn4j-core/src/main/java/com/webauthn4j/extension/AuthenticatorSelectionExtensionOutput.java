package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

public class AuthenticatorSelectionExtensionOutput extends AbstractExtensionOutput<byte[][]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("authnSel");

    @JsonCreator
    public AuthenticatorSelectionExtensionOutput(byte[][] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }
}
