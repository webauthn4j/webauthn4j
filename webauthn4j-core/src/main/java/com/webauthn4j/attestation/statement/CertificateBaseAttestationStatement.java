package com.webauthn4j.attestation.statement;

public interface CertificateBaseAttestationStatement extends AttestationStatement {

    AttestationCertificatePath getX5c();
}
