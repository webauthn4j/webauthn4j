package com.webauthn4j.extension.client;

import com.webauthn4j.extension.ExtensionIdentifier;

public class FIDOAppIDClientExtensionOutput extends AbstractClientExtensionOutput<Boolean> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("appid");

    public FIDOAppIDClientExtensionOutput(Boolean value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
