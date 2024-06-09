package com.webauthn4j.async.verifier.attestation.statement.androidkey;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AndroidKeyAttestationStatementAsyncVerifierTest {

    private final AndroidKeyAttestationStatementAsyncVerifier target = new AndroidKeyAttestationStatementAsyncVerifier();

    @Test
    void getterTest() {
        target.setTeeEnforcedOnly(false);
        assertThat(target.isTeeEnforcedOnly()).isFalse();
    }

}