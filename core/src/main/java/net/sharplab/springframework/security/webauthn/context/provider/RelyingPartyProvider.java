package net.sharplab.springframework.security.webauthn.context.provider;

import net.sharplab.springframework.security.webauthn.context.RelyingParty;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Provides {@link RelyingParty} instance
 */
public interface RelyingPartyProvider {

    RelyingParty provide(HttpServletRequest request, HttpServletResponse response);

    String getRpId();

    void setRpId(String rpId);
}
