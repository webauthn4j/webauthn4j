package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Created by ynojima on 2017/08/27.
 */
public class SelfAttestationProhibitedException extends AuthenticationException {
    public SelfAttestationProhibitedException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public SelfAttestationProhibitedException(String msg) {
        super(msg);
    }
}
