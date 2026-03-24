package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.NoOriginPredicate;
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

    @Deprecated
    @Test
    void shouldVerifyFailWhenTopOriginIsPresentButCrossOriginIsFalseAndForceBlockCrossOriginIsTrue() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");
        Origin expectedTopOrigin = new Origin("http://example.net");

        target.setForceBlockCrossOrigin(true);

        // Defense-in-depth: Malicious client sends topOrigin but crossOrigin=false
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, false, collectedTopOrigin, null);
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

    @Test
    void shouldVerifyFailWhenNoOriginPredicateIsUsedWithCrossOriginTrue() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOriginPredicate(new NoOriginPredicate())
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifyFailWhenNoOriginPredicateIsUsedWithTopOriginPresent() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");

        // Defense-in-depth: Even if crossOrigin is false, topOrigin presence should be rejected with NoOriginPredicate
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, false, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOriginPredicate(new NoOriginPredicate())
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifySuccessWhenNoOriginPredicateIsUsedWithoutCrossOrigin() {
        Origin origin = new Origin("https://example.com");

        // Same-origin scenario: crossOrigin=false (or null) and topOrigin=null
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, false, null, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                .topOriginPredicate(new NoOriginPredicate())
                .build();
        assertThatCode(() -> target.verify(collectedClientData, serverProperty)).doesNotThrowAnyException();
    }

    @Test
    void shouldVerifyFailWhenTopOriginPredicateIsNullWithCrossOriginTrue() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, true, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                // topOriginPredicate is not set (null)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifyFailWhenTopOriginPredicateIsNullWithTopOriginPresent() {
        Origin origin = new Origin("https://example.com");
        Origin collectedTopOrigin = new Origin("http://example.net");

        // Defense-in-depth: Even if crossOrigin is false, topOrigin presence should be rejected when topOriginPredicate is null
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, false, collectedTopOrigin, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                // topOriginPredicate is not set (null)
                .build();
        assertThatThrownBy(() -> target.verify(collectedClientData, serverProperty)).isInstanceOf(BadTopOriginException.class);
    }

    @Test
    void shouldVerifySuccessWhenTopOriginPredicateIsNullWithoutCrossOrigin() {
        Origin origin = new Origin("https://example.com");

        // Same-origin scenario: crossOrigin=false (or null) and topOrigin=null
        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.WEBAUTHN_CREATE, TestDataUtil.createChallenge(), origin, false, null, null);
        ServerProperty serverProperty = ServerProperty.builder()
                .origin(origin)
                .rpId("example.com")
                .challenge(TestDataUtil.createChallenge())
                // topOriginPredicate is not set (null)
                .build();
        assertThatCode(() -> target.verify(collectedClientData, serverProperty)).doesNotThrowAnyException();
    }

}