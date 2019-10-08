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

import java.security.KeyStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.AssertUtil;

/**
 * Loads {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map} from Java KeyStore object.
 */
public class KeyStoreTrustAnchorsProvider extends CachingTrustAnchorsProviderBase {

    // ~ Instance fields
    // ================================================================================================

    private KeyStore keyStoreObject;

    // ~ Methods
    // ========================================================================================================
    private void checkConfig() {
        AssertUtil.notNull(keyStoreObject, "keyStore object must not be null");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors() {
        checkConfig();
        KeyStore keyStoreObject = getKeyStoreObject();
        try  {
            List<String> aliases = Collections.list(keyStoreObject.aliases());
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (String alias : aliases) {
                X509Certificate certificate = (X509Certificate) keyStoreObject.getCertificate(alias);
                trustAnchors.add(new TrustAnchor(certificate, null));
            }
            return Collections.singletonMap(null, trustAnchors);
        } catch (java.security.KeyStoreException e) {
            throw new KeyStoreException("Failed to load TrustAnchor from keystore object", e);
        }
    }

    /**
     * Provides keyStore object
     *
     * @return keyStore object
     */
    public KeyStore getKeyStoreObject() {
        return keyStoreObject;
    }

    /**
     * Sets keyStore object
     *
     * @param keyStoreObject keyStore object
     */
    public void setKeyStoreObject(KeyStore keyStoreObject) {
        this.keyStoreObject = keyStoreObject;
    }

}
