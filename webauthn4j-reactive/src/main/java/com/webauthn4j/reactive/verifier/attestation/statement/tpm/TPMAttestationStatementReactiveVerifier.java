package com.webauthn4j.reactive.verifier.attestation.statement.tpm;

import com.webauthn4j.reactive.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyDecoder;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyVerifier;

public class TPMAttestationStatementReactiveVerifier extends AttestationStatementVerifierDelegate {
    public TPMAttestationStatementReactiveVerifier() {
        super(new TPMAttestationStatementVerifier());
    }

    public TPMDevicePropertyVerifier getTPMDevicePropertyVerifier() {
        return getTPMAttestationStatementVerifier().getTPMDevicePropertyVerifier();
    }

    public void setTPMDevicePropertyVerifier(TPMDevicePropertyVerifier tpmDevicePropertyVerifier) {
        getTPMAttestationStatementVerifier().setTPMDevicePropertyVerifier(tpmDevicePropertyVerifier);
    }

    public TPMDevicePropertyDecoder getTPMDevicePropertyDecoder() {
        return getTPMAttestationStatementVerifier().getTPMDevicePropertyDecoder();
    }

    public void setTPMDevicePropertyDecoder(TPMDevicePropertyDecoder tpmDevicePropertyDecoder) {
        getTPMAttestationStatementVerifier().setTPMDevicePropertyDecoder(tpmDevicePropertyDecoder);
    }


    private TPMAttestationStatementVerifier getTPMAttestationStatementVerifier(){
        return (TPMAttestationStatementVerifier)this.attestationStatementVerifier;
    }

}
