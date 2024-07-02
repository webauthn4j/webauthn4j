package com.webauthn4j.reactive.verifier.attestation.statement.packed;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;

public class PackedAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {

    public PackedAttestationStatementReactiveVerifier() {
        super(new PackedAttestationStatementVerifier());
    }
}
