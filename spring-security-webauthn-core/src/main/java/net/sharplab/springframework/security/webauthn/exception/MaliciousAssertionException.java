package net.sharplab.springframework.security.webauthn.exception;


import org.springframework.security.core.AuthenticationException;

public class MaliciousAssertionException extends AuthenticationException {
    public MaliciousAssertionException(String message) {
        super(message);
    }

    public MaliciousAssertionException(String message, Throwable cause) {
        super(message, cause);
    }
}