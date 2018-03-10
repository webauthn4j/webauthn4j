package net.sharplab.springframework.security.webauthn.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * UnsupportedArgumentException
 */
public class UnsupportedArgumentException extends AuthenticationException {
    public UnsupportedArgumentException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public UnsupportedArgumentException(String msg) {
        super(msg);
    }
}
