package net.sharplab.springframework.security.webauthn.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * Created by ynojima on 2017/08/15.
 */
public class MissingChallengeException extends AuthenticationException {
    public MissingChallengeException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public MissingChallengeException(String msg) {
        super(msg);
    }
}
