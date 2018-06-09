package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;

public class SimpleTransactionAuthorizationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<String> {

    public static final String ID = "txAuthSimple";

    @JsonCreator
    public SimpleTransactionAuthorizationAuthenticatorExtensionOutput(String value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
