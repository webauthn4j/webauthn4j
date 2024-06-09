package com.webauthn4j.async.verifier.attestation.statement.tpm;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;

public class NullTPMAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public NullTPMAttestationStatementAsyncVerifier() {
        super(new NullTPMAttestationStatementVerifier());
    }
}
