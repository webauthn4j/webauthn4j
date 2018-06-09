package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.List;

public class SupportedExtensionsAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<List<String>> {

    public static final String ID = "exts";

    @JsonCreator
    public SupportedExtensionsAuthenticatorExtensionOutput(List<String> value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
