package com.webauthn4j.validator.exception;

import org.checkerframework.checker.nullness.qual.Nullable;

public class IllegalBackupStateException extends ValidationException {

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
