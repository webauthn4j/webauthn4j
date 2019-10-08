/*
 * Copyright 2002-2019 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.CertificateUtil;

public class KeyStoreTrustAnchorsProviderTest {

    private KeyStoreTrustAnchorsProvider target;

    @Test
    void provide_test() throws Exception {
        target = new KeyStoreTrustAnchorsProvider();
        Path path = Paths.get(ClassLoader.getSystemResource("com/webauthn4j/anchor/KeyStoreFileTrustAnchorsProviderTest/test.jks").toURI());
        InputStream inputStream = Files.newInputStream(path);
        KeyStore keyStoreObject = loadKeyStoreFromStream(inputStream, "password");
        target.setKeyStoreObject(keyStoreObject);

        Map<AAGUID, Set<TrustAnchor>> trustAnchors = target.provide();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void provide_test_with_invalid_object() throws Exception {
        target = new KeyStoreTrustAnchorsProvider();
        target.setKeyStoreObject(CertificateUtil.createKeyStore());

        assertThrows(KeyStoreException.class,
                () -> target.provide()
        );
    }

    private KeyStore loadKeyStoreFromStream(InputStream inputStream, String password)
            throws CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStoreObject = CertificateUtil.createKeyStore();
        keyStoreObject.load(inputStream, password.toCharArray());
        return keyStoreObject;
    }
}
