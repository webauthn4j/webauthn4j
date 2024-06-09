package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

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
