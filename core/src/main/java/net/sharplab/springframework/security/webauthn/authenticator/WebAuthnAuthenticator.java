package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAttestedCredentialData;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

import java.io.Serializable;

/**
 * Web AuthN Authenticator
 */
public interface WebAuthnAuthenticator extends Serializable {

    String getName();

    WebAuthnUserDetails getUser();

    WebAuthnAttestedCredentialData getAttestationData();

    WebAuthnAttestationStatement getAttestationStatement();

    String getFormat();

}
