package com.webauthn4j.async.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;

/**
 * Since android safety-net attestation is deprecated, NullAndroidSafetyNetAttestationStatementAsyncVerifier is deprecated
 * @deprecated Since Android Safety-Net Attestation is deprecated, this verifier is deprecated
 */
@Deprecated(forRemoval = false)
public class NullAndroidSafetyNetAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public NullAndroidSafetyNetAttestationStatementAsyncVerifier() {
        super(new NullAndroidSafetyNetAttestationStatementVerifier());
    }
}
