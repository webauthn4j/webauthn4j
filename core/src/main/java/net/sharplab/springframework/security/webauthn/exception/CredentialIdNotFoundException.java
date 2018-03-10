package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if an authentication request is rejected because credentialId is not found.
 */
public class CredentialIdNotFoundException extends AuthenticationException {
    public CredentialIdNotFoundException(String msg) {
        super(msg);
    }

    public CredentialIdNotFoundException(String msg, Throwable cause) {
        super(msg, cause);
    }
}