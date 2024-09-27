package com.webauthn4j.async.verifier.attestation.statement.androidkey;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;

public class NullAndroidKeyAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {

    public NullAndroidKeyAttestationStatementAsyncVerifier() {
        super(new NullAndroidKeyAttestationStatementVerifier());
    }
}
