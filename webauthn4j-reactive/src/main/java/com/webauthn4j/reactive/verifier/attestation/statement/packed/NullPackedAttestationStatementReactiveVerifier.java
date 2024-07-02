package com.webauthn4j.reactive.verifier.attestation.statement.packed;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;

public class NullPackedAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public NullPackedAttestationStatementReactiveVerifier() {
        super(new NullPackedAttestationStatementVerifier());
    }
}
