package com.webauthn4j.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;

public class NullCertPathTrustworthinessValidator implements CertPathTrustworthinessValidator {
    @Override
    public void validate(CertificateBaseAttestationStatement attestationStatement) {
        // nop
    }
}
