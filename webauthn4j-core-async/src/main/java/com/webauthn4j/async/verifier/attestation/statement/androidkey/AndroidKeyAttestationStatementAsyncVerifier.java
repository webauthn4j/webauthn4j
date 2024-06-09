package com.webauthn4j.async.verifier.attestation.statement.androidkey;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;

public class AndroidKeyAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {

    public AndroidKeyAttestationStatementAsyncVerifier() {
        super(new AndroidKeyAttestationStatementVerifier());
    }

    public boolean isTeeEnforcedOnly() {
        return ((AndroidKeyAttestationStatementVerifier)this.attestationStatementVerifier).isTeeEnforcedOnly();
    }

    public void setTeeEnforcedOnly(boolean teeEnforcedOnly) {
        ((AndroidKeyAttestationStatementVerifier)this.attestationStatementVerifier).setTeeEnforcedOnly(teeEnforcedOnly);
    }
}
