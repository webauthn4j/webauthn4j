package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.Coordinates;

public class LocationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<Coordinates> {

    public static final String ID = "loc";

    @JsonCreator
    public LocationAuthenticatorExtensionOutput(Coordinates value) {
        super(value);
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

}
