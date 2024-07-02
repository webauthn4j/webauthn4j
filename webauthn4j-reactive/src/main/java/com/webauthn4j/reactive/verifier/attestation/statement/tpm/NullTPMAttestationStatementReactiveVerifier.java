package com.webauthn4j.reactive.verifier.attestation.statement.tpm;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;

public class NullTPMAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public NullTPMAttestationStatementReactiveVerifier() {
        super(new NullTPMAttestationStatementVerifier());
    }
}
