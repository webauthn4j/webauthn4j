package com.webauthn4j.test.client;

import com.webauthn4j.extension.ExtensionIdentifier;

public class SupportedExtensionsClientExtensionInput extends AbstractClientExtensionInput<Boolean> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    public SupportedExtensionsClientExtensionInput(Boolean value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }
}
