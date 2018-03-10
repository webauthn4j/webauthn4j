package net.sharplab.springframework.security.webauthn.sample.domain.exception;

import org.terasoluna.gfw.common.message.ResultMessages;

/**
 * EntityNotFoundException for WebAuthn Sample
 */
@SuppressWarnings("squid:MaximumInheritanceDepth")
public class WebAuthnSampleEntityNotFoundException extends WebAuthnSampleBusinessException {


    /**
     * Constructor for specify a message.
     * <p>
     * generate a {@link ResultMessages} instance of error type and add a message.
     * </p>
     *
     * @param message result message
     */
    public WebAuthnSampleEntityNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructor for specify messages.
     * <p>
     * Takes multiple {@code String} messages as argument.
     * </p>
     *
     * @param messages {@link ResultMessages} instance
     */
    public WebAuthnSampleEntityNotFoundException(ResultMessages messages) {
        super(messages);
    }

    /**
     * Constructor for specify messages and exception.
     * <p>
     * Takes multiple {@code String} messages and cause of exception as argument.
     * </p>
     *
     * @param messages {@link ResultMessages} instance
     * @param cause    {@link Throwable} instance
     */
    public WebAuthnSampleEntityNotFoundException(ResultMessages messages, Throwable cause) {
        super(messages, cause);
    }
}
