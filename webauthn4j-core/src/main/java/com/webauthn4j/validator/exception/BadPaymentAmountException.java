package com.webauthn4j.validator.exception;

import org.checkerframework.checker.nullness.qual.Nullable;

/**
 * Thrown if a bad payment amount is specified
 */
public class BadPaymentAmountException extends ValidationException {
    public BadPaymentAmountException(@Nullable String message) {
        super(message);
    }

    public BadPaymentAmountException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

}
