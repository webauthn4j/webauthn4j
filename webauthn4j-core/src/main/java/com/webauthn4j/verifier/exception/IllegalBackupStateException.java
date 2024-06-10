package com.webauthn4j.verifier.exception;

import org.jetbrains.annotations.Nullable;

public class IllegalBackupStateException extends VerificationException {

    public IllegalBackupStateException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public IllegalBackupStateException(@Nullable String message) {
        super(message);
    }

    public IllegalBackupStateException(@Nullable Throwable cause) {
        super(cause);
    }
}
