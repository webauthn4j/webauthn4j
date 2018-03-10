package net.sharplab.springframework.security.webauthn;

import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * WebAuthnAssertionAuthenticationToken
 */
public class WebAuthnAssertionAuthenticationToken extends AbstractAuthenticationToken {

    // ~ Instance fields
    // ================================================================================================

    private WebAuthnAuthenticationContext credentials;


    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>WebAuthnAssertionAuthenticationToken</code>, as the {@link #isAuthenticated()}
     * will return <code>false</code>.
     *
     * @param credentials credential
     */
    public WebAuthnAssertionAuthenticationToken(WebAuthnAuthenticationContext credentials) {
        super(null);
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * The identity of the principal being authenticated. In the case of an authentication
     * request with username and password, this would be the username. Callers are
     * expected to populate the principal for an authentication request.
     * <p>
     * The <tt>AuthenticationManager</tt> implementation will often return an
     * <tt>Authentication</tt> containing richer information as the principal for use by
     * the application. Many of the authentication providers will create a
     * {@code UserDetails} object as the principal.
     *
     * @return the <code>Principal</code> being authenticated or the authenticated
     * principal after authentication.
     */
    @Override
    public String getPrincipal() {
        return null;
    }

    /**
     * The credentials that prove the principal is correct. This is usually a password,
     * but could be anything relevant to the <code>AuthenticationManager</code>. Callers
     * are expected to populate the credentials.
     *
     * @return the credentials that prove the identity of the <code>Principal</code>
     */
    @Override
    public WebAuthnAuthenticationContext getCredentials() {
        return credentials;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted");
        }

        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAssertionAuthenticationToken)) return false;
        if (!super.equals(o)) return false;

        WebAuthnAssertionAuthenticationToken that = (WebAuthnAssertionAuthenticationToken) o;

        return credentials != null ? credentials.equals(that.credentials) : that.credentials == null;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (credentials != null ? credentials.hashCode() : 0);
        return result;
    }
}
