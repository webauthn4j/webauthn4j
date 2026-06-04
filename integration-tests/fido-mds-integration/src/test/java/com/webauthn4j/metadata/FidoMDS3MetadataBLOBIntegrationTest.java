package com.webauthn4j.metadata;

import com.webauthn4j.async.metadata.FidoMDS3MetadataBLOBAsyncProvider;
import com.webauthn4j.async.metadata.HttpAsyncClient;
import com.webauthn4j.async.util.internal.FileAsyncUtil;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBPayload;
import com.webauthn4j.util.Base64Util;
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

    private static final X509Certificate ROOT_CERTIFICATE = CertificateUtil.generateX509Certificate(Base64Util.decode(
            "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G" +
                    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp" +
                    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4" +
                    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG" +
                    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI" +
                    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8" +
                    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT" +
                    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm" +
                    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd" +
                    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ" +
                    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw" +
                    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o" +
                    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU" +
                    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp" +
                    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK" +
                    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX" +
                    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs" +
                    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH" +
                    "WD9f"));

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
        Path rootCertificatePath = new File("src/test/resources/integration/component/root-r3.crt").toPath();
        byte[] rootCertificateBytes = FileAsyncUtil.load(rootCertificatePath).toCompletableFuture().get();
        X509Certificate rootCertificate = CertificateUtil.generateX509Certificate(rootCertificateBytes);

        Path gsextendvalsha2g3r3CrlPath = new File("src/test/resources/integration/component/gsextendvalsha2g3r3.crl").toPath();
        byte[] crlBytes = FileAsyncUtil.load(gsextendvalsha2g3r3CrlPath).toCompletableFuture().get();

        Path rootR3CrlPath = new File("src/test/resources/integration/component/root-r3.crl").toPath();
        byte[] rootR3CrlBytes = FileAsyncUtil.load(rootR3CrlPath).toCompletableFuture().get();

        HttpAsyncClient httpAsyncClient = mock(HttpAsyncClient.class);
        when(httpAsyncClient.fetch(FidoMDS3MetadataBLOBAsyncProvider.DEFAULT_BLOB_ENDPOINT))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(blobBytes))));
        when(httpAsyncClient.fetch("http://crl.globalsign.com/gs/gsextendvalsha2g3r3.crl"))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(crlBytes))));
        when(httpAsyncClient.fetch("http://crl.globalsign.com/root-r3.crl"))
                .thenReturn(CompletableFuture.completedFuture(new HttpClient.Response(200, new ByteArrayInputStream(rootR3CrlBytes))));

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
