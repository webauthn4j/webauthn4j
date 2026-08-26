package com.webauthn4j.metadata;

import com.webauthn4j.async.metadata.FidoMDS3MetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.HttpAsyncClient;
import com.webauthn4j.async.util.internal.FileAsyncUtil;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FidoMDS3MetadataBLOBIntegrationTest {

    private static final X509Certificate ROOT_CERTIFICATE = CertificateUtil.generateX509Certificate(
            FidoMDS3MetadataBLOBIntegrationTest.class.getResourceAsStream("/integration/component/root-r46.crt"));

    private byte[] blobBytes;

    @BeforeAll
    void fetchBlobFromFidoMds() {
        SimpleHttpClient httpClient = new SimpleHttpClient();
        HttpClient.Response response = httpClient.fetch(FidoMDS3MetadataBLOBProvider.DEFAULT_BLOB_ENDPOINT);
        try {
            blobBytes = response.getBody().readAllBytes();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    @Test
    void sync_test() {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.fetch(FidoMDS3MetadataBLOBProvider.DEFAULT_BLOB_ENDPOINT))
                .thenReturn(new HttpClient.Response(200, new ByteArrayInputStream(blobBytes)));
        FidoMDS3MetadataBLOBProvider target = new FidoMDS3MetadataBLOBProvider(
                new ObjectConverter(),
                FidoMDS3MetadataBLOBProvider.DEFAULT_BLOB_ENDPOINT,
                httpClient,
                Collections.singleton(new TrustAnchor(ROOT_CERTIFICATE, null)));
        MetadataBLOB metadataBLOB = target.provide();
        assertThat(metadataBLOB).isNotNull();
    }

    @Test
    void metadata_blob_payload_should_cover_all_fields() {
        String blobJwt = new String(blobBytes, StandardCharsets.UTF_8).trim();

        JsonMapper strictMapper = new ObjectConverter()
                .rebuildWithJSONModule(new WebAuthnMetadataJSONModule())
                .getJsonMapper().rebuild()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
                .build();

        String[] parts = blobJwt.split("\\.");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);

        assertThatCode(() -> strictMapper.readValue(payloadJson, MetadataBLOBPayload.class))
                .doesNotThrowAnyException();
    }

    @Test
    void async_test() throws ExecutionException, InterruptedException {
        Path rootCertificatePath = new File("src/test/resources/integration/component/root-r46.crt").toPath();
        byte[] rootCertificateBytes = FileAsyncUtil.load(rootCertificatePath).toCompletableFuture().get();
        X509Certificate rootCertificate = CertificateUtil.generateX509Certificate(rootCertificateBytes);

        Path gsgccr46evtlsca2025CrlPath = new File("src/test/resources/integration/component/gsgccr46evtlsca2025.crl").toPath();
        byte[] crlBytes = FileAsyncUtil.load(gsgccr46evtlsca2025CrlPath).toCompletableFuture().get();

        Path rootR46CrlPath = new File("src/test/resources/integration/component/root-r46.crl").toPath();
        byte[] rootR46CrlBytes = FileAsyncUtil.load(rootR46CrlPath).toCompletableFuture().get();

        HttpAsyncClient httpAsyncClient = mock(HttpAsyncClient.class);
        when(httpAsyncClient.fetch(FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(blobBytes))));
        when(httpAsyncClient.fetch("http://crl.globalsign.com/gsgccr46evtlsca2025.crl"))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(crlBytes))));
        when(httpAsyncClient.fetch("http://crl.globalsign.com/rootr46.crl"))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(rootR46CrlBytes))));

        FidoMDS3MetadataBLOBAsyncProvider target = new FidoMDS3MetadataBLOBAsyncProvider(
                new ObjectConverter(),
                FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT,
                httpAsyncClient,
                Collections.singleton(new TrustAnchor(rootCertificate, null)));
        var metadataBlob = target.provide().toCompletableFuture().get();
        assertThatCode(metadataBlob::getPayload).doesNotThrowAnyException();
        assertThat(metadataBlob.getPayload().getEntries()).isNotEmpty();
    }
}
