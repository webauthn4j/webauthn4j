package net.sharplab.springframework.security.webauthn.attestation.statement;

import java.io.Serializable;
import java.security.cert.X509Certificate;

/**
 * Attestation metadata.certs container
 */
public interface WebAuthnAttestationStatement extends Serializable {
    String getFormat();

    boolean isSelfAttested();

    X509Certificate getEndEntityCertificate();
}
