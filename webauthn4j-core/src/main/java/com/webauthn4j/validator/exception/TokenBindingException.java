package com.webauthn4j.validator.exception;

public class TokenBindingException extends ValidationException {

    public TokenBindingException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenBindingException(String message) {
        super(message);
    }

    public TokenBindingException(Throwable cause) {
        super(cause);
    }
}
