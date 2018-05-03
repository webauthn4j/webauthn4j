package net.sharplab.springframework.security.webauthn.sample.domain.exception;

import org.terasoluna.gfw.common.exception.ExceptionCodeProvider;

/**
 * System Exception for WebAuthn Sample
 */
@SuppressWarnings("squid:MaximumInheritanceDepth")
public class WebAuthnSystemException extends org.terasoluna.gfw.common.exception.SystemException {


    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider}, message to be displayed and underlying cause of exception can be specified.
     * </p>
     *
     * @param code    ExceptionCode {@link ExceptionCodeProvider}
     * @param message message to be displayed
     * @param cause   underlying cause of exception
     */
    public WebAuthnSystemException(String code, String message, Throwable cause) {
        super(code, message, cause);
    }

    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider}, message to be displayed can be specified.
     * </p>
     *
     * @param code    ExceptionCode {@link ExceptionCodeProvider}
     * @param message message to be displayed
     */
    public WebAuthnSystemException(String code, String message) {
        super(code, message);
    }

    /**
     * Constructor<br>
     * <p>
     * {@link ExceptionCodeProvider} and underlying cause of exception can be specified.
     * </p>
     *
     * @param code  ExceptionCode {@link ExceptionCodeProvider}
     * @param cause underlying cause of exception
     */
    public WebAuthnSystemException(String code, Throwable cause) {
        super(code, cause);
    }
}
