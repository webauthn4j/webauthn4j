package com.webauthn4j.metadata.exception;

import org.jetbrains.annotations.Nullable;


public class CertPathCheckException extends RuntimeException {
    public CertPathCheckException(@Nullable String message, @Nullable Throwable cause) {
        super(message, cause);
    }

    public CertPathCheckException(@Nullable String message) {
        super(message);
    }

    public CertPathCheckException(@Nullable Throwable cause) {
        super(cause);
    }
}
