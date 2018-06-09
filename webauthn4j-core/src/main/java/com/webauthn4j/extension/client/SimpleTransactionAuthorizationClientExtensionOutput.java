package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;

public class SimpleTransactionAuthorizationClientExtensionOutput extends AbstractClientExtensionOutput<String> {

    public static final String ID = "txAuthSimple";

    @JsonCreator
    public SimpleTransactionAuthorizationClientExtensionOutput(String value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
