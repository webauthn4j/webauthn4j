package com.webauthn4j.reactive.verifier.attestation.statement.androidkey;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;

public class NullAndroidKeyAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {

    public NullAndroidKeyAttestationStatementReactiveVerifier() {
        super(new NullAndroidKeyAttestationStatementVerifier());
    }
}
