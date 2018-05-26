package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.List;

public class AuthenticatorSelectionExtensionOutput extends AbstractExtensionOutput<List<byte[]>> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("authnSel");

    @JsonCreator
    public AuthenticatorSelectionExtensionOutput(List<byte[]> value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }
}
