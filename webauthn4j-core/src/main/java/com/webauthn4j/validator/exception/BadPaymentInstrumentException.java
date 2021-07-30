package com.webauthn4j.validator.exception;

import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Thrown if bad payment instrument is specified
 */
public class BadPaymentInstrumentException extends ValidationException {

    public BadPaymentInstrumentException(@Nullable String message) {
        super(message);
    }

}
