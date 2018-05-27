package com.webauthn4j.validator.exception;

public class UnexpectedExtensionException extends ValidationException {
    public UnexpectedExtensionException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnexpectedExtensionException(String message) {
        super(message);
    }

    public UnexpectedExtensionException(Throwable cause) {
        super(cause);
    }
}
