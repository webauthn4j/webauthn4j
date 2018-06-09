package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.List;

public class SupportedExtensionsClientExtensionOutput extends AbstractClientExtensionOutput<List<String>> {

    public static final String ID = "exts";

    @JsonCreator
    public SupportedExtensionsClientExtensionOutput(List<String> value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
