package com.webauthn4j.reactive.metadata.anchor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.reactive.metadata.LocalFileMetadataBLOBReactiveProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedTrustAnchorReactiveRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void test() throws ExecutionException, InterruptedException, IOException {

        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);

        LocalFileMetadataBLOBReactiveProvider localFileMetadataBLOBReactiveProvider = new LocalFileMetadataBLOBReactiveProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedTrustAnchorReactiveRepository target = new MetadataBLOBBasedTrustAnchorReactiveRepository(localFileMetadataBLOBReactiveProvider);
        var result = target.find(new AAGUID("08987058-CADC-4B81-B6E1-30DE50DCBE96")).toCompletableFuture().get();
        assertThat(result).hasSize(1);
    }

}