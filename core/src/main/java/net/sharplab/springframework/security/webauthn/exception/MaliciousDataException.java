package net.sharplab.springframework.security.webauthn.exception;


import org.springframework.security.core.AuthenticationException;

public class MaliciousDataException extends AuthenticationException {
    public MaliciousDataException(String message) {
        super(message);
    }

    public MaliciousDataException(String message, Throwable cause) {
        super(message, cause);
    }
}