package net.sharplab.springframework.security.webauthn.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Created by ynojima on 2017/08/29.
 */
public class CertificateException extends AuthenticationException {
    public CertificateException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public CertificateException(String msg) {
        super(msg);
    }
}
