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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
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

class KeyStoreTrustAnchorRepositoryTest {

    private static final String RESOURCE_DIR = "com/webauthn4j/anchor/KeyStoreFileTrustAnchorsProviderTest/";
    private static final String PASSWORD = "password";

    @Nested
    class Pkcs12KeyStoreTest {

        private Path keyStorePath;
        private KeyStoreTrustAnchorRepository target;

        @BeforeEach
        void setUp() throws Exception {
            keyStorePath = Paths.get(ClassLoader.getSystemResource(RESOURCE_DIR + "test.p12").toURI());
            target = KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(keyStorePath, PASSWORD);
        }

        @Test
        void shouldReturnAllTrustAnchorsRegardlessOfSearchParameters() {
            AAGUID aaguid = new AAGUID(UUID.randomUUID());
            byte[] keyId = new byte[32];

            Set<TrustAnchor> trustAnchorsFromAAGUID = target.find(aaguid);
            Set<TrustAnchor> trustAnchorsFromKeyId = target.find(keyId);

            assertAll(
                    () -> assertThat(trustAnchorsFromAAGUID).hasSize(1),
                    () -> assertThat(trustAnchorsFromKeyId).hasSize(1),
                    () -> assertThat(trustAnchorsFromAAGUID).isEqualTo(trustAnchorsFromKeyId)
            );
        }

        @Test
        void shouldCreateRepositoryFromKeyStoreObject() throws Exception {
            KeyStore keyStore = CertificateUtil.createKeyStore();
            keyStore.load(Files.newInputStream(keyStorePath), PASSWORD.toCharArray());

            KeyStoreTrustAnchorRepository repository = new KeyStoreTrustAnchorRepository(keyStore);
            Set<TrustAnchor> trustAnchors = repository.find(new AAGUID(UUID.randomUUID()));

            assertThat(trustAnchors).hasSize(1);
        }

        @Test
        void shouldThrowExceptionWhenPasswordIsIncorrect() {
            assertThatThrownBy(() ->
                    KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(keyStorePath, "wrongPassword")
            ).isInstanceOf(KeyStoreException.class);
        }
    }

    @Nested
    class JksKeyStoreTest {

        private Path keyStorePath;

        @BeforeEach
        void setUp() throws Exception {
            Assumptions.assumeTrue(isJksAvailable());
            keyStorePath = Paths.get(ClassLoader.getSystemResource(RESOURCE_DIR + "test.jks").toURI());
        }

        @Test
        void shouldReturnAllTrustAnchors() {
            KeyStoreTrustAnchorRepository target =
                    KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(keyStorePath, PASSWORD);
            Set<TrustAnchor> trustAnchors = target.find(new AAGUID(UUID.randomUUID()));
            assertThat(trustAnchors).hasSize(1);
        }

        private boolean isJksAvailable() {
            try {
                KeyStore.getInstance("JKS");
                return true;
            } catch (java.security.KeyStoreException e) {
                return false;
            }
        }
    }

    @Test
    void shouldThrowExceptionWhenKeyStoreFilePathIsInvalid() {
        Path invalidPath = Paths.get("invalid/path/to/keystore.p12");

        assertThatThrownBy(() ->
                KeyStoreTrustAnchorRepository.createFromKeyStoreFilePath(invalidPath, PASSWORD)
        ).isInstanceOf(KeyStoreException.class);
    }
}
