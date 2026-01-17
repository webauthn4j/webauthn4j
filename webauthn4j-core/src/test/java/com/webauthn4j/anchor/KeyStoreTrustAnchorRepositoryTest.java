/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

/**
 * Test class for {@link KeyStoreTrustAnchorRepository}
 * This test verifies that the repository correctly loads trust anchors from a KeyStore file
 * and returns them regardless of search parameters.
 */
class KeyStoreTrustAnchorRepositoryTest {

    private Path keyStorePath;
    private KeyStoreTrustAnchorRepository target;
    private final String password = "password";

    @BeforeEach
    void setUp() throws Exception {
        keyStorePath = Paths.get(ClassLoader.getSystemResource("com/webauthn4j/anchor/KeyStoreFileTrustAnchorsProviderTest/test.jks").toURI());
        target = KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(keyStorePath, password);
    }

    @Test
    void shouldReturnAllTrustAnchorsRegardlessOfSearchParameters() {
        // AAGUID-based lookup
        Set<TrustAnchor> trustAnchorsFromAAGUID = target.find(new AAGUID(UUID.randomUUID()));
        
        // Key-identifier-based lookup
        Set<TrustAnchor> trustAnchorsFromKeyId = target.find(new byte[32]);
        
        assertAll(
            () -> assertThat(trustAnchorsFromAAGUID).hasSize(1),
            () -> assertThat(trustAnchorsFromKeyId).hasSize(1),
            // All the results should be identical since this implementation returns all anchors
            () -> assertThat(trustAnchorsFromAAGUID).isEqualTo(trustAnchorsFromKeyId)
        );
    }

    @Test
    void shouldCreateRepositoryFromKeyStoreObject() throws Exception {
        KeyStore keyStore = CertificateUtil.createKeyStore();
        keyStore.load(Files.newInputStream(keyStorePath), password.toCharArray());
        
        KeyStoreTrustAnchorRepository repository = new KeyStoreTrustAnchorRepository(keyStore);
        Set<TrustAnchor> trustAnchors = repository.find(new AAGUID(UUID.randomUUID()));
        
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    void shouldThrowExceptionWhenKeyStoreFilePathIsInvalid() {
        Path invalidPath = Paths.get("invalid/path/to/keystore.jks");
        
        assertThatThrownBy(() -> 
            KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(invalidPath, password)
        ).isInstanceOf(KeyStoreException.class);
    }

    @Test
    void shouldThrowExceptionWhenPasswordIsIncorrect() {
        assertThatThrownBy(() -> 
            KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(keyStorePath, "wrongPassword")
        ).isInstanceOf(KeyStoreException.class);
    }

}