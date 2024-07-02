package com.webauthn4j.reactive.verifier.attestation.statement.androidkey;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidkey.AndroidKeyAttestationStatementVerifier;

public class AndroidKeyAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {

    public AndroidKeyAttestationStatementReactiveVerifier() {
        super(new AndroidKeyAttestationStatementVerifier());
    }

    public boolean isTeeEnforcedOnly() {
        return ((AndroidKeyAttestationStatementVerifier)this.attestationStatementVerifier).isTeeEnforcedOnly();
    }

    public void setTeeEnforcedOnly(boolean teeEnforcedOnly) {
        ((AndroidKeyAttestationStatementVerifier)this.attestationStatementVerifier).setTeeEnforcedOnly(teeEnforcedOnly);
    }
}
