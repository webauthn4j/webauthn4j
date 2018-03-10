package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for Web Authentication specification.
 */
public class WebAuthnAuthenticationToken extends AbstractAuthenticationToken {

    private Serializable principal;
    private WebAuthnAuthenticationContext credentials;

    public WebAuthnAuthenticationToken(Serializable principal, WebAuthnAuthenticationContext credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.setAuthenticated(true);
    }

    @Override
    public Serializable getPrincipal() {
        return principal;
    }

    @Override
    public WebAuthnAuthenticationContext getCredentials() {
        return credentials;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAuthenticationToken)) return false;
        if (!super.equals(o)) return false;

        WebAuthnAuthenticationToken that = (WebAuthnAuthenticationToken) o;

        if (principal != null ? !principal.equals(that.principal) : that.principal != null) return false;
        return credentials != null ? credentials.equals(that.credentials) : that.credentials == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (principal != null ? principal.hashCode() : 0);
        result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
        return result;
    }
}
