package com.webauthn4j.test.authenticator;

import com.webauthn4j.extension.ExtensionIdentifier;

public class FIDOAppIDClientExtensionInput extends AbstractAuthenticatorExtensionInput<String> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("appid");

    public FIDOAppIDClientExtensionInput(String value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
