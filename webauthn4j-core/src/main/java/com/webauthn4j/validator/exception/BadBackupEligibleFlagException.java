package com.webauthn4j.validator.exception;

import org.jetbrains.annotations.Nullable;

public class BadBackupEligibleFlagException extends ValidationException{

    public BadBackupEligibleFlagException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public BadBackupEligibleFlagException(@Nullable String message) {
        super(message);
    }

    public BadBackupEligibleFlagException(@Nullable Throwable cause) {
        super(cause);
    }
}
