package com.webauthn4j.async.verifier.attestation.statement.none;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;

public class NoneAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {

    public NoneAttestationStatementAsyncVerifier() {
        super(new NoneAttestationStatementVerifier());
    }
}
