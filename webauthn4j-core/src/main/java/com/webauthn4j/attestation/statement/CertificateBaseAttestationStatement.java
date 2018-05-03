package com.webauthn4j.attestation.statement;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;

public interface CertificateBaseAttestationStatement extends AttestationStatement {

    CertPath getX5c();

    X509Certificate getEndEntityCertificate();
}
