package com.webauthn4j.reactive.verifier.attestation.statement.u2f;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;

public class NullFIDOU2FAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public NullFIDOU2FAttestationStatementReactiveVerifier() {
        super(new NullFIDOU2FAttestationStatementVerifier());
    }
}
