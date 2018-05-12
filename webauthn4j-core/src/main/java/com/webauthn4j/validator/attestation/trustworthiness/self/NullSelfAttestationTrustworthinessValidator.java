package com.webauthn4j.validator.attestation.trustworthiness.self;

import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;

public class NullSelfAttestationTrustworthinessValidator implements SelfAttestationTrustworthinessValidator {
    @Override
    public void validate(CertificateBaseAttestationStatement attestationStatement) {
        // nop
    }
}
