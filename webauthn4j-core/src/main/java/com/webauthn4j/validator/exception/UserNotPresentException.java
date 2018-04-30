package com.webauthn4j.validator.exception;

/**
 * UserNotPresentException
 */
public class UserNotPresentException extends ValidationException {

    public UserNotPresentException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserNotPresentException(String message) {
        super(message);
    }
}
