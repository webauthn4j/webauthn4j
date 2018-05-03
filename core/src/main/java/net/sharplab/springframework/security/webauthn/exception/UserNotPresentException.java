package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

public class UserNotPresentException  extends AuthenticationException {

    public UserNotPresentException(String message, Throwable cause) {
        super(message, cause);
    }

    public UserNotPresentException(String message) {
        super(message);
    }
}
