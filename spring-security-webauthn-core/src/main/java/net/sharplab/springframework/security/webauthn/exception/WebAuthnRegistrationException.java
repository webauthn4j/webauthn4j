package net.sharplab.springframework.security.webauthn.exception;

public class WebAuthnRegistrationException extends RuntimeException {
    public WebAuthnRegistrationException(String message, Throwable cause) {
        super(message, cause);
    }

    public WebAuthnRegistrationException(String message) {
        super(message);
    }

    public WebAuthnRegistrationException(Throwable cause) {
        super(cause);
    }

}
