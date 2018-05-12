package com.webauthn4j.validator.attestation.trustworthiness.ecdaa;

import com.webauthn4j.attestation.statement.AttestationStatement;

public class NullECDAATrustworthinessValidator implements ECDAATrustworthinessValidator {
    @Override
    public void validate(AttestationStatement attestationStatement) {
        // nop
    }
}
