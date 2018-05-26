package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.List;

public class SupportedExtensionsExtensionOutput extends AbstractExtensionOutput<List<String>> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    @JsonCreator
    public SupportedExtensionsExtensionOutput(List<String> value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
