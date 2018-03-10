package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.exception.CredentialIdNotFoundException;

/**
 * A {@link WebAuthnAuthenticatorService} implementation that retrieves the user details
 * from a database using JDBC queries.
 */
public class JdbcWebAuthnAuthenticatorServiceImpl implements WebAuthnAuthenticatorService {

    /**
     * Locates the user based on the username. In the actual implementation, the search may possibly be case
     * insensitive, or case insensitive depending on how the implementation instance is configured. In this case, the
     * <code>UserDetails</code> object that comes back may have a username that is of a different case than what was
     * actually requested..
     *
     * @param credentialId the credentialId identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws CredentialIdNotFoundException if the user could not be found or the user has no GrantedAuthority
     */
    @Override
    public WebAuthnAuthenticator loadWebAuthnAuthenticatorByCredentialId(byte[] credentialId) {
        return null;
    }
}
