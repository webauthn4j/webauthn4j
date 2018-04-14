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

import com.webauthn4j.exception.CertificateException;
import com.webauthn4j.exception.KeyStoreLoadException;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.Experimental;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Provides {@link TrustAnchor}'{@link Set} backed by Java KeyStore file.
 */
@Experimental
public class KeyStoreTrustAnchorProvider {

    //~ Instance fields ================================================================================================

    /**
     * Provides {@link TrustAnchor}'{@link Set} backed by Java KeyStore file.
     *
     * @param keystore         KeyStore file path
     * @param password         KeyStore file password
     * @return {@link TrustAnchor}'{@link Set}
     */
    public Set<TrustAnchor> provide(Path keystore, String password) {
        try(InputStream inputStream = Files.newInputStream(keystore)){
            KeyStore keyStore = loadKeyStoreFromStream(inputStream, password);
            try {
                List<String> aliases = Collections.list(keyStore.aliases());
                Set<TrustAnchor> trustAnchors = new HashSet<>();
                for (String alias : aliases) {
                    X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                    trustAnchors.add(new TrustAnchor(certificate, null)); //TODO: null?
                }
                return trustAnchors;
            } catch (KeyStoreException e) {
                throw new KeyStoreLoadException("Certificate load error", e);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

    }

    private KeyStore loadKeyStoreFromStream(InputStream inputStream, String password) {
        KeyStore keyStore = CertificateUtil.createKeyStore();
        try {
            keyStore.load(inputStream, password.toCharArray());
        } catch (IOException e) {
            throw new KeyStoreLoadException("IO Error", e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreLoadException("No such algorithm", e);
        } catch (java.security.cert.CertificateException e) {
            throw new CertificateException("Certificate validation failed", e);
        }
        return keyStore;
    }
}
