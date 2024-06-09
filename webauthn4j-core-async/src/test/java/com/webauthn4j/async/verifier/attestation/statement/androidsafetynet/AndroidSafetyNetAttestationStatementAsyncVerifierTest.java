package com.webauthn4j.async.verifier.attestation.statement.androidsafetynet;

import com.webauthn4j.verifier.attestation.statement.androidsafetynet.GooglePlayServiceVersionVerifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AndroidSafetyNetAttestationStatementAsyncVerifierTest {

    @Test
    void getter_setter_test(){
        AndroidSafetyNetAttestationStatementAsyncVerifier target = new AndroidSafetyNetAttestationStatementAsyncVerifier();
        target.setForwardThreshold(1);
        assertThat(target.getForwardThreshold()).isEqualTo(1);
        target.setBackwardThreshold(2);
        assertThat(target.getBackwardThreshold()).isEqualTo(2);
        GooglePlayServiceVersionVerifier verifier = mock(GooglePlayServiceVersionVerifier.class);
        target.setVersionVerifier(verifier);
        assertThat(target.getVersionVerifier()).isEqualTo(verifier);
    }

}