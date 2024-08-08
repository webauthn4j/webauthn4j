package com.webauthn4j.async.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class KeyStoreTrustAnchorAsyncRepositoryTest {

    @Test
    void find_return_all_trustAnchors_to_any_parameters_test() throws Exception {
        Path path = Paths.get(ClassLoader.getSystemResource("com/webauthn4j/async/anchor/KeyStoreTrustAnchorAsyncRepositoryTest/test.jks").toURI());
        KeyStoreTrustAnchorAsyncRepository target = KeyStoreTrustAnchorAsyncRepository.createFromKeyStoreFilePath(path, "password").toCompletableFuture().get();
        Set<TrustAnchor> trustAnchors;
        trustAnchors = target.find(new AAGUID(UUID.randomUUID())).toCompletableFuture().get();
        assertThat(trustAnchors).hasSize(1);
        trustAnchors = target.find(new byte[32]).toCompletableFuture().get();
        assertThat(trustAnchors).hasSize(1);
    }

}