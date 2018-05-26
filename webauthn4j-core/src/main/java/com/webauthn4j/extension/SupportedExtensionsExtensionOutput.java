package com.webauthn4j.extension;

import java.util.List;

public class SupportedExtensionsExtensionOutput implements ExtensionOutput {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("exts");

    private List<String> exts;

    public SupportedExtensionsExtensionOutput(List<String> exts) {
        this.exts = exts;
    }

    public SupportedExtensionsExtensionOutput() {}

    public List<String> getExts() {
        return exts;
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

    @Override
    public void validate() {

    }
}
