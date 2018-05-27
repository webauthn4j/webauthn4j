package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.ExtensionIdentifier;

public class SimpleTransactionAuthorizationClientExtensionOutput extends AbstractClientExtensionOutput<String> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("txAuthSimple");

    @JsonCreator
    public SimpleTransactionAuthorizationClientExtensionOutput(String value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
