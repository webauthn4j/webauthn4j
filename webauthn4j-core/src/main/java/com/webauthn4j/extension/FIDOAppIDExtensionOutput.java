package com.webauthn4j.extension;

public class FIDOAppIDExtensionOutput extends AbstractExtensionOutput<Boolean> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("appid");

    public FIDOAppIDExtensionOutput(Boolean value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
