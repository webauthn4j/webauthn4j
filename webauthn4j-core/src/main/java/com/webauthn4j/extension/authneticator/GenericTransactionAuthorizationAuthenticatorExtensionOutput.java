package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;

public class GenericTransactionAuthorizationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<byte[]> {

    public static final String ID = "txAuthGeneric";

    @JsonCreator
    public GenericTransactionAuthorizationAuthenticatorExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
