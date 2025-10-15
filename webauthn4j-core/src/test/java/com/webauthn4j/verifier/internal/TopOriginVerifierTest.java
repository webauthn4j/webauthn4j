package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.exception.BadTopOriginException;
import com.webauthn4j.verifier.exception.CrossOriginException;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TopOriginVerifierTest {

    private final TopOriginVerifier target = new TopOriginVerifier();

    @Test
    void shouldVerifySuccessWhenServerPropertyTopOriginMatchesCollectedTopOrigin() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Origin expectedTopOrigin = new Origin("http://example.net");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOrigin(expectedTopOrigin)
                .build();
        assertThatCode(() -> target.verify(collectedClientData, serverProperty)).doesNotThrowAnyException();
    }

    @Test
    void shouldVerifySuccessWhenAnyTopOriginPredicateIsUsed() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .anyTopOrigin()
                .build();
        assertThatCode(() -> target.verify(collectedClientData, serverProperty)).doesNotThrowAnyException();
    }

    @Deprecated
    @Test
    void shouldVerifyFailWhenServerPropertyTopOriginMatchesCollectedTopOriginButForceBlockCrossOriginIsTrue() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Origin expectedTopOrigin = new Origin("http://example.net");

        target.setForceBlockCrossOrigin(true);

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOrigin(expectedTopOrigin)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(CrossOriginException.class);
    }

    @Test
    void shouldVerifyFailWhenServerPropertyTopOriginDoesNotMatchCollectedTopOrigin() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Origin expectedTopOrigin = new Origin("http://example.org");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOrigin(expectedTopOrigin)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifyFailWhenServerPropertyTopOriginDoesNotContainCollectedTopOrigin() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Set<Origin> expectedTopOrigins = Set.of(new Origin("http://example.org"), new Origin("http://example.io"));

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOrigins(expectedTopOrigins)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifyFailWhenServerPropertyTopOriginPredicateDoesNotMatchCollectedTopOrigin() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Origin expectedTopOrigin = new Origin("http://example.org");
        OriginPredicate expectedTopOriginPredicate = new OriginPredicate() {
            @Override
            public boolean test(Origin origin) {
                return expectedTopOrigin.equals(origin);
            }
        };

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOriginPredicate(expectedTopOriginPredicate)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }



}