package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

public class SimpleTransactionAuthorizationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<String> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("txAuthSimple");

    @JsonCreator
    public SimpleTransactionAuthorizationAuthenticatorExtensionOutput(String value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
