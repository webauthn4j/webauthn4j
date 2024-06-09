package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.metadata.LocalFileMetadataBLOBAsyncProvider;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.verifier.RegistrationObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedTrustAnchorAsyncRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(new AAGUID("08987058-CADC-4B81-B6E1-30DE50DCBE96")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(HexUtil.decode("2fea8f357c7a54a57f45cda72fafb34d1d449fd4")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void validate_test() throws ExecutionException, InterruptedException {
        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        @SuppressWarnings("ConstantConditions")
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        assertThat(target.find(aaguid).toCompletableFuture().get()).isNotEmpty();
    }

    @Test
    void setNotFidoCertifiedAllowed_test() throws ExecutionException, InterruptedException {
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setNotFidoCertifiedAllowed(false);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105")).toCompletableFuture().get();
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();

        target.setNotFidoCertifiedAllowed(true);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void setSelfAssertionSubmittedAllowed_test() throws ExecutionException, InterruptedException {
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorAsyncRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setSelfAssertionSubmittedAllowed(false);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a")).toCompletableFuture().get();
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();

        target.setSelfAssertionSubmittedAllowed(true);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a")).toCompletableFuture().get();
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    private MetadataBLOBBasedTrustAnchorAsyncRepository createWithBlob(String filePath){
        try {
            Path blobPath = new File(filePath).toPath();
            Path dstPath = tempDir.resolve("blob.jwt");
            Files.copy(blobPath, dstPath);
            LocalFileMetadataBLOBAsyncProvider localFileMetadataBLOBAsyncProvider = new LocalFileMetadataBLOBAsyncProvider(new ObjectConverter(), dstPath);
            return new MetadataBLOBBasedTrustAnchorAsyncRepository(localFileMetadataBLOBAsyncProvider);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


}