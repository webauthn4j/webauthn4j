package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * UserNotVerifiedException
 */
public class UserNotVerifiedException extends AuthenticationException {

    public UserNotVerifiedException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserNotVerifiedException(String message) {
        super(message);
    }
}
