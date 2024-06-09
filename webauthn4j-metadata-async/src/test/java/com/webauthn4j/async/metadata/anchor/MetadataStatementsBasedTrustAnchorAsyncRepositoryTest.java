package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataStatementsBasedTrustAnchorAsyncRepositoryTest {

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws ExecutionException, InterruptedException {
        Path jsonFilePath = new File("src/test/resources/com/webauthn4j/async/metadata/JsonMetadataItem_u2f.json").toPath();
        MetadataStatementsBasedTrustAnchorAsyncRepository repository = new MetadataStatementsBasedTrustAnchorAsyncRepository(new ObjectConverter(), jsonFilePath);
        Set<TrustAnchor> trustAnchors = repository.find(HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573")).toCompletableFuture().get();
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    void find_by_aaguid_test() throws ExecutionException, InterruptedException {
        Path jsonFilePath = new File("src/test/resources/com/webauthn4j/async/metadata/JsonMetadataItem_fido2.json").toPath();
        MetadataStatementsBasedTrustAnchorAsyncRepository repository = new MetadataStatementsBasedTrustAnchorAsyncRepository(new ObjectConverter(), jsonFilePath);
        Set<TrustAnchor> trustAnchors = repository.find(new AAGUID("0132d110-bf4e-4208-a403-ab4f5f12efe5")).toCompletableFuture().get();
        assertThat(trustAnchors).hasSize(1);
    }

}