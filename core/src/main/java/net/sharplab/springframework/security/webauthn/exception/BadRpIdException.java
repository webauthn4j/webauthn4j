package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * BadRpIdException
 */
public class BadRpIdException extends AuthenticationException {
    public BadRpIdException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public BadRpIdException(String msg) {
        super(msg);
    }
}
