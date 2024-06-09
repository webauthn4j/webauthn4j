package com.webauthn4j.async.verifier.attestation.statement.packed;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;

public class PackedAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {

    public PackedAttestationStatementAsyncVerifier() {
        super(new PackedAttestationStatementVerifier());
    }
}
