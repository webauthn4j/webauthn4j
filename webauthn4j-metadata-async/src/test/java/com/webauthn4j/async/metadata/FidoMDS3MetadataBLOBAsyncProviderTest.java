package com.webauthn4j.async.metadata;

import com.webauthn4j.async.util.internal.FileAsyncUtil;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.HttpClient;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class FidoMDS3MetadataBLOBAsyncProviderTest {

    @Test
    void test() throws ExecutionException, InterruptedException {
        Path rootCertificatePath = new File("src/test/resources/integration/component/root-r3.crt").toPath();
        byte[] rootCertificateBytes = FileAsyncUtil.load(rootCertificatePath).toCompletableFuture().get();
        X509Certificate rootCertificate = CertificateUtil.generateX509Certificate(rootCertificateBytes);

        Path gsextendvalsha2g3r3CrlPath = new File("src/test/resources/integration/component/gsextendvalsha2g3r3.crl").toPath();
        byte[] crlBytes = FileAsyncUtil.load(gsextendvalsha2g3r3CrlPath).toCompletableFuture().get();

        Path rootR3CrlPath = new File("src/test/resources/integration/component/root-r3.crl").toPath();
        byte[] rootR3CrlBytes = FileAsyncUtil.load(rootR3CrlPath).toCompletableFuture().get();

        HttpAsyncClient httpAsyncClient = spy(new SimpleHttpAsyncClient());
        when(httpAsyncClient.fetch("http://crl.globalsign.com/gs/gsextendvalsha2g3r3.crl")).thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(crlBytes))));
        when(httpAsyncClient.fetch("http://crl.globalsign.com/root-r3.crl")).thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(rootR3CrlBytes))));
        FidoMDS3MetadataBLOBAsyncProvider target = new FidoMDS3MetadataBLOBAsyncProvider(new ObjectConverter(), FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT, httpAsyncClient, Collections.singleton(new TrustAnchor(rootCertificate, null)));
        var metadataBlob = target.provide().toCompletableFuture().get();
        assertThatCode(metadataBlob::getPayload).doesNotThrowAnyException();
        assertThat(metadataBlob.getPayload().getEntries()).isNotEmpty();
    }
}
