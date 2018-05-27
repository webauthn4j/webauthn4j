package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

import java.util.List;

public class SupportedExtensionsAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<List<String>> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    @JsonCreator
    public SupportedExtensionsAuthenticatorExtensionOutput(List<String> value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
