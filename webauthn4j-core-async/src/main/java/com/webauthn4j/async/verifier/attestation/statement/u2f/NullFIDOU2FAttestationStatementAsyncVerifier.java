package com.webauthn4j.async.verifier.attestation.statement.u2f;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;

public class NullFIDOU2FAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public NullFIDOU2FAttestationStatementAsyncVerifier() {
        super(new NullFIDOU2FAttestationStatementVerifier());
    }
}
