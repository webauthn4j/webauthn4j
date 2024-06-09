package com.webauthn4j.async.verifier.attestation.statement.packed;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;

public class NullPackedAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public NullPackedAttestationStatementAsyncVerifier() {
        super(new NullPackedAttestationStatementVerifier());
    }
}
