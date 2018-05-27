package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

public class UserVerificationIndexAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<byte[]> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("uvi");

    @JsonCreator
    public UserVerificationIndexAuthenticatorExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
