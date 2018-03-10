package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAttestedCredentialData;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

/**
 * A {@link WebAuthnAuthenticator} implementation
 */
public class WebAuthnAuthenticatorImpl implements WebAuthnAuthenticator {

    //~ Instance fields ================================================================================================
    private String name;
    private WebAuthnUserDetails user;
    private WebAuthnAttestedCredentialData attestationData;
    private WebAuthnAttestationStatement attestationStatement;

    public WebAuthnAuthenticatorImpl(String name, WebAuthnUserDetails user, WebAuthnAttestedCredentialData attestationData, WebAuthnAttestationStatement attestationStatement) {
        this.name = name;
        this.user = user;
        this.attestationData = attestationData;
        this.attestationStatement = attestationStatement;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public WebAuthnUserDetails getUser() {
        return user;
    }

    @Override
    public WebAuthnAttestedCredentialData getAttestationData() {
        return attestationData;
    }

    @Override
    public WebAuthnAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    @Override
    public String getFormat() {
        return attestationStatement.getFormat();
    }

}
