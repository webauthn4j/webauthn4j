package com.webauthn4j.async.verifier.attestation.statement.tpm;

import com.webauthn4j.async.verifier.attestation.statement.internal.AttestationStatementVerifierDelegate;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyDecoder;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyVerifier;

public class TPMAttestationStatementAsyncVerifier extends AttestationStatementVerifierDelegate {
    public TPMAttestationStatementAsyncVerifier() {
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
