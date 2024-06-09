package com.webauthn4j.async.verifier.attestation.statement.u2f;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.u2f.FIDOU2FAttestationStatementVerifier;

public class FIDOU2FAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public FIDOU2FAttestationStatementAsyncVerifier() {
        super(new FIDOU2FAttestationStatementVerifier());
    }
}
