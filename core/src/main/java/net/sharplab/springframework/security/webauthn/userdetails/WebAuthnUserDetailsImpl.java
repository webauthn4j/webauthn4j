package net.sharplab.springframework.security.webauthn.userdetails;

import net.sharplab.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

/**
 * A {@link WebAuthnUserDetails} implementation
 */
@SuppressWarnings("squid:S2160")
public class WebAuthnUserDetailsImpl extends User implements WebAuthnUserDetails {

    // ~ Instance fields
    // ================================================================================================
    private boolean passwordAuthenticationAllowed = false;
    private List<WebAuthnAuthenticator> authenticators;

    public WebAuthnUserDetailsImpl(String username, String password, List<WebAuthnAuthenticator> authenticators,
                                   Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.authenticators = authenticators;
    }

    public WebAuthnUserDetailsImpl(String username, String password, List<WebAuthnAuthenticator> authenticators,
                                   Collection<? extends GrantedAuthority> authorities, boolean passwordAuthenticationAllowed) {
        this(username, password, authenticators, authorities);
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }

    @Override
    public List<WebAuthnAuthenticator> getAuthenticators() {
        return this.authenticators;
    }

    @Override
    public boolean isPasswordAuthenticationAllowed(){
        return passwordAuthenticationAllowed;
    }

    @Override
    public void setPasswordAuthenticationAllowed(boolean passwordAuthenticationAllowed) {
        this.passwordAuthenticationAllowed = passwordAuthenticationAllowed;
    }


}
