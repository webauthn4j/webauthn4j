package com.webauthn4j.spc.verifier;

import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class DefaultBrowserBoundKeyHandler implements BrowserBoundKeyHandler {

    @Override
    public void handle(@NotNull BrowserBoundKeyEvent event) {
        if (event instanceof UnknownBrowserBoundKeyEvent) {
            throw new ConstraintViolationException(
                    "Browser bound key in clientData does not match any stored browser bound key.");
        }
        if (event instanceof MissingBrowserBoundKeyEvent) {
            throw new ConstraintViolationException(
                    "Browser bound key data is missing but stored browser bound keys exist. Possible downgrade attack.");
        }
    }
}
