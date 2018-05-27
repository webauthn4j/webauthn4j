package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

public class UserVerificationIndexClientExtensionOutput extends AbstractClientExtensionOutput<byte[]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("uvi");

    @JsonCreator
    public UserVerificationIndexClientExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
