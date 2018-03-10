package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * BadOriginException
 */
public class BadOriginException extends AuthenticationException {
    public BadOriginException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadOriginException(String message) {
        super(message);
    }
}
