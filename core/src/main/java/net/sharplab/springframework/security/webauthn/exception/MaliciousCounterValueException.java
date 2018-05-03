package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

public class MaliciousCounterValueException extends AuthenticationException {
    public MaliciousCounterValueException(String message) {
        super(message);
    }

    public MaliciousCounterValueException(String message, Throwable cause) {
        super(message, cause);
    }
}