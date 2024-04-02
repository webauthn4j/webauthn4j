package com.webauthn4j.validator.exception;

import org.checkerframework.checker.nullness.qual.Nullable;

public class CredentialIdTooLongException extends ValidationException{

    public CredentialIdTooLongException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public CredentialIdTooLongException(@Nullable String message) {
        super(message);
    }

    public CredentialIdTooLongException(@Nullable Throwable cause) {
        super(cause);
    }
}
