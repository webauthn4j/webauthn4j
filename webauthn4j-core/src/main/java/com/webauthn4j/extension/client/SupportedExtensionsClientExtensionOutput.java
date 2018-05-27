package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

import java.util.List;

public class SupportedExtensionsClientExtensionOutput extends AbstractClientExtensionOutput<List<String>> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    @JsonCreator
    public SupportedExtensionsClientExtensionOutput(List<String> value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
