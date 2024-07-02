package com.webauthn4j.reactive.verifier.attestation.statement.apple;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;

public class AppleAnonymousAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public AppleAnonymousAttestationStatementReactiveVerifier() {
        super(new AppleAnonymousAttestationStatementVerifier());
    }
}
