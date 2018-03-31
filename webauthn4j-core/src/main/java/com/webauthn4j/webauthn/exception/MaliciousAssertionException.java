package com.webauthn4j.webauthn.exception;

public class MaliciousAssertionException extends ValidationException {
    public MaliciousAssertionException(String message) {
        super(message);
    }

    public MaliciousAssertionException(String message, Throwable cause) {
        super(message, cause);
    }
}