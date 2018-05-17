package com.webauthn4j.test.authenticator.model;

public class WebAuthnModelException extends RuntimeException {

    public WebAuthnModelException(String message, Throwable cause) {
        super(message, cause);
    }

    public WebAuthnModelException(String message) {
        super(message);
    }

    public WebAuthnModelException(Throwable e) {
        super(e);
    }

    public WebAuthnModelException() {
    }
}
