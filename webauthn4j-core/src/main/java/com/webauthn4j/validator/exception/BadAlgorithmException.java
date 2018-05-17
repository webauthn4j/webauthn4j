package com.webauthn4j.validator.exception;

public class BadAlgorithmException extends ValidationException {
    public BadAlgorithmException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadAlgorithmException(String message) {
        super(message);
    }

    public BadAlgorithmException(Throwable cause) {
        super(cause);
    }
}
