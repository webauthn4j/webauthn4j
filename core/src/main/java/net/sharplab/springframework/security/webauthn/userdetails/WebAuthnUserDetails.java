package net.sharplab.springframework.security.webauthn.userdetails;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * WebAuthnUserDetails
 */
public interface WebAuthnUserDetails extends UserDetails {

    Collection<? extends WebAuthnAuthenticator> getAuthenticators();

    boolean isPasswordAuthenticationAllowed();

    void setPasswordAuthenticationAllowed(boolean passwordAuthenticationAllowed);

}
