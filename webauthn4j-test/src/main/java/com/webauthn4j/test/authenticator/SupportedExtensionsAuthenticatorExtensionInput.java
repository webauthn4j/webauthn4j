package com.webauthn4j.test.authenticator;

public class SupportedExtensionsAuthenticatorExtensionInput extends AbstractAuthenticatorExtensionInput<Boolean> {

    public static final String ID = "exts";

    public SupportedExtensionsAuthenticatorExtensionInput(Boolean value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }
}
