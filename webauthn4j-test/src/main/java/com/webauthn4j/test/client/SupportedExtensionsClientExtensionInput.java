package com.webauthn4j.test.client;

public class SupportedExtensionsClientExtensionInput extends AbstractClientExtensionInput<Boolean> {

    public static final String ID = "exts";

    public SupportedExtensionsClientExtensionInput(Boolean value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }
}
