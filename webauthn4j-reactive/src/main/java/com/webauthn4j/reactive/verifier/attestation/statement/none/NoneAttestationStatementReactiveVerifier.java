package com.webauthn4j.reactive.verifier.attestation.statement.none;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;

public class NoneAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {

    public NoneAttestationStatementReactiveVerifier() {
        super(new NoneAttestationStatementVerifier());
    }
}
