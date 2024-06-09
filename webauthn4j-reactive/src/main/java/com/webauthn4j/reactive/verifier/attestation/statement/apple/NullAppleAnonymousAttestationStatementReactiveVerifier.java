package com.webauthn4j.reactive.verifier.attestation.statement.apple;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementVerifier;

public class NullAppleAnonymousAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public NullAppleAnonymousAttestationStatementReactiveVerifier() {
        super(new NullAppleAnonymousAttestationStatementVerifier());
    }
}
