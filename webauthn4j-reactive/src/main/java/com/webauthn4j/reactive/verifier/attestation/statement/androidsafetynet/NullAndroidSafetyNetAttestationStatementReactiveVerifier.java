package com.webauthn4j.reactive.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;

/**
 * Since android safety-net attestation is deprecated, NullAndroidSafetyNetAttestationStatementReactiveVerifier is deprecated
 */
@Deprecated
public class NullAndroidSafetyNetAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public NullAndroidSafetyNetAttestationStatementReactiveVerifier() {
        super(new NullAndroidSafetyNetAttestationStatementVerifier());
    }
}
