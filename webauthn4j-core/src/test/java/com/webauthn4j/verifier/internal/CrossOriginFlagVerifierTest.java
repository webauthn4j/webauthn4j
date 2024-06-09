package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.exception.CrossOriginException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class CrossOriginFlagVerifierTest {

    @Test
    void verify_with_expected_crossOrigin_test() {
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, null);
        CrossOriginFlagVerifier.verify(collectedClientData, true);
    }

    @Test
    void verify_with_unexpected_crossOrigin_test() {
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, null);
        assertThrows(CrossOriginException.class,
                () -> CrossOriginFlagVerifier.verify(collectedClientData, false)
        );
    }
}
