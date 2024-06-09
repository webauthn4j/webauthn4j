package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AggregatingTrustAnchorAsyncRepositoryTest {

    @Test
    void find_by_aaguid_test() throws ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        TrustAnchor trustAnchorA = mock(TrustAnchor.class);
        TrustAnchor trustAnchorB = mock(TrustAnchor.class);
        TrustAnchorAsyncRepository mockA = mock(TrustAnchorAsyncRepository.class);
        TrustAnchorAsyncRepository mockB = mock(TrustAnchorAsyncRepository.class);
        when(mockA.find(aaguid)).thenReturn(CompletableFuture.completedFuture(Collections.singleton(trustAnchorA)));
        when(mockB.find(aaguid)).thenReturn(CompletableFuture.completedFuture(Collections.singleton(trustAnchorB)));
        TrustAnchorAsyncRepository target = new AggregatingTrustAnchorAsyncRepository(mockA, mockB);
        assertThat(target.find(aaguid).toCompletableFuture().get()).containsExactlyInAnyOrder(trustAnchorA, trustAnchorB);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws ExecutionException, InterruptedException {
        byte[] attestationCertificateKeyIdentifier = new byte[32];
        TrustAnchor trustAnchorA = mock(TrustAnchor.class);
        TrustAnchor trustAnchorB = mock(TrustAnchor.class);
        TrustAnchorAsyncRepository mockA = mock(TrustAnchorAsyncRepository.class);
        TrustAnchorAsyncRepository mockB = mock(TrustAnchorAsyncRepository.class);
        when(mockA.find(attestationCertificateKeyIdentifier)).thenReturn(CompletableFuture.completedFuture(Collections.singleton(trustAnchorA)));
        when(mockB.find(attestationCertificateKeyIdentifier)).thenReturn(CompletableFuture.completedFuture(Collections.singleton(trustAnchorB)));
        TrustAnchorAsyncRepository target = new AggregatingTrustAnchorAsyncRepository(mockA, mockB);
        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).containsExactlyInAnyOrder(trustAnchorA, trustAnchorB);
    }

}