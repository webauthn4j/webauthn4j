package com.webauthn4j.extension.client;

public class FIDOAppIDClientExtensionOutput extends AbstractClientExtensionOutput<Boolean> {

    public static final String ID = "appid";

    public FIDOAppIDClientExtensionOutput(Boolean value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
