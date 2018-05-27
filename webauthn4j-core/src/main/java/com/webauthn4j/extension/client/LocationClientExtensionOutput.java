package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.Coordinates;
import com.webauthn4j.extension.ExtensionIdentifier;

public class LocationClientExtensionOutput extends AbstractClientExtensionOutput<Coordinates> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("loc");

    @JsonCreator
    public LocationClientExtensionOutput(Coordinates value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
