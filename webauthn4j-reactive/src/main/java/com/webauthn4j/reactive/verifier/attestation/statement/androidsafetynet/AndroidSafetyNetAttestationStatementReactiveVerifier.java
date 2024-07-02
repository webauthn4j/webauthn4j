package com.webauthn4j.reactive.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.AndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.GooglePlayServiceVersionVerifier;
import org.jetbrains.annotations.NotNull;

/**
 * Since android safety-net attestation is deprecated, AndroidSafetyNetAttestationStatementReactiveVerifier is deprecated
 */
@Deprecated
public class AndroidSafetyNetAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public AndroidSafetyNetAttestationStatementReactiveVerifier() {
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
