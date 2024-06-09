package com.webauthn4j.async.verifier.attestation.statement.apple;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.apple.NullAppleAnonymousAttestationStatementVerifier;

public class NullAppleAnonymousAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public NullAppleAnonymousAttestationStatementAsyncVerifier() {
        super(new NullAppleAnonymousAttestationStatementVerifier());
    }
}
