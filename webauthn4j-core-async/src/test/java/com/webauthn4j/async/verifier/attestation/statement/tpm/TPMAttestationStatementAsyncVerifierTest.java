package com.webauthn4j.async.verifier.attestation.statement.tpm;

import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyDecoder;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDevicePropertyVerifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class TPMAttestationStatementAsyncVerifierTest {

    @Test
    void getter_setter_test(){
        TPMAttestationStatementAsyncVerifier target = new TPMAttestationStatementAsyncVerifier();

        TPMDevicePropertyVerifier tpmDevicePropertyVerifier = mock(TPMDevicePropertyVerifier.class);
        target.setTPMDevicePropertyVerifier(tpmDevicePropertyVerifier);
        assertThat(target.getTPMDevicePropertyVerifier()).isEqualTo(tpmDevicePropertyVerifier);

        TPMDevicePropertyDecoder tpmDevicePropertyDecoder = mock(TPMDevicePropertyDecoder.class);
        target.setTPMDevicePropertyDecoder(tpmDevicePropertyDecoder);
        assertThat(target.getTPMDevicePropertyDecoder()).isEqualTo(tpmDevicePropertyDecoder);
    }

}