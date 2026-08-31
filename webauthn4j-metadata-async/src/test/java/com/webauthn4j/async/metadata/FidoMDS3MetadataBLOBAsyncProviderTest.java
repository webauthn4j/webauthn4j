package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FidoMDS3MetadataBLOBAsyncProviderTest {

    @Test
    void certPathValidation_is_executed_on_the_default_executor_test() {
        FidoMDS3MetadataBLOBAsyncProvider target = new FidoMDS3MetadataBLOBAsyncProvider(
                new ObjectConverter(),
                FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT,
                mock(HttpAsyncClient.class),
                Collections.emptySet());
        CertPathCheckContext context = mock(CertPathCheckContext.class);
        when(context.getCertPath()).thenReturn(CertificateUtil.generateCertPath(Collections.emptyList()));
        when(context.getTrustAnchors()).thenReturn(Collections.singleton(new TrustAnchor(mock(X509Certificate.class), null)));
        when(context.isRevocationCheckEnabled()).thenReturn(false);

        CompletionStage<Void> result = target.getCertPathAsyncValidator().check(context);

        assertThatThrownBy(() -> result.toCompletableFuture().join())
                .isInstanceOf(CompletionException.class);
    }

    @Test
    void certPathValidation_is_delegated_to_the_configured_executor_test() {
        AtomicReference<Runnable> submittedTask = new AtomicReference<>();
        Executor executor = submittedTask::set;
        FidoMDS3MetadataBLOBAsyncProvider target = new FidoMDS3MetadataBLOBAsyncProvider(
                new ObjectConverter(),
                FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT,
                mock(HttpAsyncClient.class),
                Collections.<TrustAnchor>emptySet(),
                executor);

        CompletionStage<Void> result = target.getCertPathAsyncValidator().check(mock(CertPathCheckContext.class));

        assertThat(submittedTask.get()).isNotNull();
        assertThat(result.toCompletableFuture()).isNotDone();
    }
}
