package net.sharplab.springframework.security.webauthn.context.provider;

import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides {@link WebAuthnRegistrationContext} instance
 */
public interface WebAuthnRegistrationContextProvider {

    WebAuthnRegistrationContext provide(HttpServletRequest request,
                                        HttpServletResponse response,
                                        String clientDataBase64,
                                        String attestationObjectBase64);
}
