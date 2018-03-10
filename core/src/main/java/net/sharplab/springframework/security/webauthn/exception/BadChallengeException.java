package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * BadChallengeException
 */
public class BadChallengeException extends AuthenticationException {

    public BadChallengeException(String message, Throwable cause) {
        super(message, cause);
    }

    public BadChallengeException(String message) {
        super(message);
    }
}
