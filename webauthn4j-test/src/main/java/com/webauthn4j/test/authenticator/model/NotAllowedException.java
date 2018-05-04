package com.webauthn4j.test.authenticator.model;

public class NotAllowedException extends WebAuthnModelException {

    public NotAllowedException(String message, Throwable cause) {
        super(message, cause);
    }

    public NotAllowedException(String message) {
        super(message);
    }

    public NotAllowedException(Throwable e) {
        super(e);
    }
}
