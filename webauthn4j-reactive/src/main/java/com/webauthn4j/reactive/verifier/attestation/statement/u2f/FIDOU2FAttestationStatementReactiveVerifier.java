package com.webauthn4j.reactive.verifier.attestation.statement.u2f;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;

public class FIDOU2FAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public FIDOU2FAttestationStatementReactiveVerifier() {
        super(new FIDOU2FAttestationStatementVerifier());
    }
}
