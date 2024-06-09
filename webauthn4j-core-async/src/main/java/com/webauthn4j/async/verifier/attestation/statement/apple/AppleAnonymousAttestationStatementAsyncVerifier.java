package com.webauthn4j.async.verifier.attestation.statement.apple;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.apple.AppleAnonymousAttestationStatementVerifier;

public class AppleAnonymousAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public AppleAnonymousAttestationStatementAsyncVerifier() {
        super(new AppleAnonymousAttestationStatementVerifier());
    }
}
