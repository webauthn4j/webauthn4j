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

package com.webauthn4j.webauthn.anchor;

import com.webauthn4j.fido.exception.KeyStoreLoadException;
import com.webauthn4j.webauthn.exception.CertificateException;
import com.webauthn4j.webauthn.util.CertificateUtil;
import org.springframework.core.io.Resource;

import java.io.IOException;
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
public class KeyStoreTrustAnchorProvider {

    //~ Instance fields ================================================================================================

    /**
     * Provides {@link TrustAnchor}'{@link Set} backed by Java KeyStore file.
     *
     * @param keyStoreResource KeyStore file resource
     * @param password         KeyStore file password
     * @return {@link TrustAnchor}'{@link Set}
     */
    public Set<TrustAnchor> provide(Resource keyStoreResource, String password) {
        KeyStore keyStore = loadKeyStoreFromResource(keyStoreResource, password);
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
    }

    private KeyStore loadKeyStoreFromResource(Resource keyStoreResource, String password) {
        KeyStore keyStore = CertificateUtil.generateKeyStore();
        try {
            keyStore.load(keyStoreResource.getInputStream(), password.toCharArray());
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
