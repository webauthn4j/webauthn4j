package com.webauthn4j.validator.exception;

public class MaliciousCounterValueException extends ValidationException {
    public MaliciousCounterValueException(String message) {
        super(message);
    }

    public MaliciousCounterValueException(String message, Throwable cause) {
        super(message, cause);
    }
}