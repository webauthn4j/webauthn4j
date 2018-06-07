package com.webauthn4j.test.authenticator;

import com.webauthn4j.extension.ExtensionIdentifier;

public class SupportedExtensionsAuthenticatorExtensionInput extends AbstractAuthenticatorExtensionInput<Boolean> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    public SupportedExtensionsAuthenticatorExtensionInput(Boolean value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }
}
