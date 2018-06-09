package com.webauthn4j.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.Coordinates;

public class LocationClientExtensionOutput extends AbstractClientExtensionOutput<Coordinates> {

    public static final String ID = "loc";

    @JsonCreator
    public LocationClientExtensionOutput(Coordinates value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
