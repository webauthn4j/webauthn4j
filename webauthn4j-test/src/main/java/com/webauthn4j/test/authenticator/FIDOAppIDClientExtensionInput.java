package com.webauthn4j.test.authenticator;

public class FIDOAppIDClientExtensionInput extends AbstractAuthenticatorExtensionInput<String> {

    public static final String ID = "appid";

    public FIDOAppIDClientExtensionInput(String value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
