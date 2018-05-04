package com.webauthn4j.test.authenticator.model;

public class NotSupportedException extends WebAuthnModelException {

    public NotSupportedException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotSupportedException(String message) {
        super(message);
    }

    public NotSupportedException(Throwable e) {
        super(e);
    }
}
