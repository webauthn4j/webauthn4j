package com.webauthn4j.test.authenticator.model;

public class InvalidStateException extends WebAuthnModelException {

    public InvalidStateException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidStateException(String message) {
        super(message);
    }

    public InvalidStateException(Throwable e) {
        super(e);
    }
}
