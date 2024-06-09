package com.webauthn4j.async.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedMetadataStatementAsyncRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("9c835346-796b-4c27-8898-d6032f515cc5");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws IOException, ExecutionException, InterruptedException {
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("1434d2f277fe479c35ddf6aa4d08a07cbce99dd7");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier).toCompletableFuture().get()).hasSize(1);
    }

    @Test
    void notFidoCertifiedAllowed_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("3789da91-f943-46bc-95c3-50ea2012f03a");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);
        target.setNotFidoCertifiedAllowed(false);
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void selfAssertionSubmittedAllowed_test() throws IOException, ExecutionException, InterruptedException {
        AAGUID aaguid = new AAGUID("01d993d9-33d7-4db5-a7a9-7edc56ddfdb5");
        Path blobPath = new File("src/test/resources/integration/component/test-blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBAsyncProvider metadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementAsyncRepository target = new MetadataBLOBBasedMetadataStatementAsyncRepository(metadataBLOBAsyncProvider);

        target.setSelfAssertionSubmittedAllowed(false);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isEmpty();

        target.setSelfAssertionSubmittedAllowed(true);
        assertThat(target.find(aaguid).toCompletableFuture().get()).hasSize(1);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }


}