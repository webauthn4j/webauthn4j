package com.webauthn4j.extension.authneticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.extension.Coordinates;
import com.webauthn4j.extension.ExtensionIdentifier;

public class LocationAuthenticatorExtensionOutput extends AbstractAuthenticatorExtensionOutput<Coordinates> {

    public static final ExtensionIdentifier ID = new ExtensionIdentifier("loc");

    @JsonCreator
    public LocationAuthenticatorExtensionOutput(Coordinates value) {
        super(value);
    }

    @Override
    public ExtensionIdentifier getIdentifier() {
        return ID;
    }

}
