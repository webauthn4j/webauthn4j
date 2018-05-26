package com.webauthn4j.extension;

import com.fasterxml.jackson.annotation.JsonCreator;

public class SimpleTransactionAuthorizationExtensionOutput extends AbstractExtensionOutput<String> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("txAuthSimple");

    @JsonCreator
    public SimpleTransactionAuthorizationExtensionOutput(String value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
