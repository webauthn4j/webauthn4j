package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

public class GenericTransactionAuthorizationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<byte[]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("txAuthGeneric");

    @JsonCreator
    public GenericTransactionAuthorizationAuthenticatorExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
