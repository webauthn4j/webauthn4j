package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;

public class UserVerificationIndexAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<byte[]> {

    public static final String ID = "uvi";

    @JsonCreator
    public UserVerificationIndexAuthenticatorExtensionOutput(byte[] value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
