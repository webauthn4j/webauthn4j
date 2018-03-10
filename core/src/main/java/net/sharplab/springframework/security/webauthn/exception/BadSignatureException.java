package net.sharplab.springframework.security.webauthn.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * BadSignatureException
 */
public class BadSignatureException extends AuthenticationException {
    public BadSignatureException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public BadSignatureException(String msg) {
        super(msg);
    }
}
