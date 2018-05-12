package com.webauthn4j.validator.exception;

public class ConstraintViolationException extends ValidationException {

    public ConstraintViolationException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConstraintViolationException(String message) {
        super(message);
    }

}
