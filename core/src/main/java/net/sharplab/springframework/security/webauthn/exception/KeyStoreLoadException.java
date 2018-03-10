package net.sharplab.springframework.security.webauthn.exception;

/**
 * Created by ynojima on 2017/09/09.
 */
public class KeyStoreLoadException extends RuntimeException {
    public KeyStoreLoadException(String msg, Throwable cause) {
        super(msg, cause);
    }

    public KeyStoreLoadException(String msg) {
        super(msg);
    }

}
