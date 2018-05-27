package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.extension.authneticator.AbstractAuthenticatorExtensionOutput;

public class AuthenticatorSelectionClientExtensionOutput extends AbstractClientExtensionOutput<byte[][]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("authnSel");

    @JsonCreator
    public AuthenticatorSelectionClientExtensionOutput(byte[][] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }
}
