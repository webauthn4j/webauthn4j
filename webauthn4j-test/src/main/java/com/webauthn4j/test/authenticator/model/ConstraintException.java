package com.webauthn4j.test.authenticator.model;

public class ConstraintException extends WebAuthnModelException {
    public ConstraintException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConstraintException(String message) {
        super(message);
    }

    public ConstraintException(Throwable e) {
        super(e);
    }
}
