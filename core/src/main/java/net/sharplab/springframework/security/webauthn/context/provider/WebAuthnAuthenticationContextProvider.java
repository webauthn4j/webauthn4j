package net.sharplab.springframework.security.webauthn.context.provider;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides {@link WebAuthnAuthenticationContext} instance
 */
public interface WebAuthnAuthenticationContextProvider {
    WebAuthnAuthenticationContext provide(HttpServletRequest request,
                                          HttpServletResponse response,
                                          String credentialId,
                                          String clientData,
                                          String authenticatorData,
                                          String signature,
                                          Authentication authentication);
}
