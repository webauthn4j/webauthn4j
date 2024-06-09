package com.webauthn4j.async.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.GooglePlayServiceVersionVerifier;
import org.jetbrains.annotations.NotNull;

/**
 * Since android safety-net attestation is deprecated, AndroidSafetyNetAttestationStatementAsyncVerifier is deprecated
 * @deprecated Since Android Safety-Net Attestation is deprecated, this verifier is deprecated
 */
@Deprecated(forRemoval = false)
public class AndroidSafetyNetAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public AndroidSafetyNetAttestationStatementAsyncVerifier() {
        super(new AndroidSafetyNetAttestationStatementVerifier());
    }

    public int getForwardThreshold() {
        return getAndroidSafetyNetAttestationStatementVerifier().getForwardThreshold();
    }

    public void setForwardThreshold(int forwardThreshold) {
        getAndroidSafetyNetAttestationStatementVerifier().setForwardThreshold(forwardThreshold);
    }

    public int getBackwardThreshold() {
        return getAndroidSafetyNetAttestationStatementVerifier().getBackwardThreshold();
    }

    public void setBackwardThreshold(int backwardThreshold) {
        getAndroidSafetyNetAttestationStatementVerifier().setBackwardThreshold(backwardThreshold);
    }

    public @NotNull GooglePlayServiceVersionVerifier getVersionVerifier() {
        return getAndroidSafetyNetAttestationStatementVerifier().getVersionVerifier();
    }

    public void setVersionVerifier(@NotNull GooglePlayServiceVersionVerifier versionVerifier) {
        AssertUtil.notNull(versionVerifier, "versionVerifier must not be null");
        getAndroidSafetyNetAttestationStatementVerifier().setVersionVerifier(versionVerifier);
    }

    private AndroidSafetyNetAttestationStatementVerifier getAndroidSafetyNetAttestationStatementVerifier(){
        return (AndroidSafetyNetAttestationStatementVerifier)this.attestationStatementVerifier;
    }

}
