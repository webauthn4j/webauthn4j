/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.KeyStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Loads {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map} from Java KeyStore.
 */
public class KeyStoreTrustAnchorsProvider implements TrustAnchorsProvider {

    // ~ Instance fields
    // ================================================================================================

    private KeyStore keyStore;

    // ~ Methods
    // ========================================================================================================

    /**
     * {@inheritDoc}
     */
    @Override
    public @NonNull Map<AAGUID, Set<TrustAnchor>> provide() {
        return loadTrustAnchors();
    }

    /**
     * Provides keyStore object
     *
     * @return keyStore object
     */
    public @NonNull KeyStore getKeyStore() {
        return keyStore;
    }

    /**
     * Sets keyStore object
     *
     * @param keyStore keyStore object
     */
    public void setKeyStore(@NonNull KeyStore keyStore) {
        AssertUtil.notNull(keyStore, "keyStore must not be null");
        this.keyStore = keyStore;
    }

    private void checkConfig() {
        AssertUtil.notNull(keyStore, "keyStore must not be null");
    }

    private @NonNull Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors() {
        checkConfig();
        KeyStore keyStoreObject = getKeyStore();
        try {
            List<String> aliases = Collections.list(keyStoreObject.aliases());
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (String alias : aliases) {
                X509Certificate certificate = (X509Certificate) keyStoreObject.getCertificate(alias);
                trustAnchors.add(new TrustAnchor(certificate, null));
            }
            return Collections.singletonMap(AAGUID.NULL, trustAnchors);
        } catch (java.security.KeyStoreException e) {
            throw new KeyStoreException("Failed to load TrustAnchor from keystore", e);
        }
    }

}
