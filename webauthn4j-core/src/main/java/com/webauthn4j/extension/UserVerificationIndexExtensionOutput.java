package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

public class UserVerificationIndexExtensionOutput extends AbstractExtensionOutput<byte[]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("uvi");

    @JsonCreator
    public UserVerificationIndexExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
