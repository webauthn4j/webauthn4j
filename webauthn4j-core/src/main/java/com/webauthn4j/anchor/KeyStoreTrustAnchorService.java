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

import com.webauthn4j.util.Experimental;

import java.io.*;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * KeyStore backed TrustAnchorService
 * Load a key store at first time access and cache it.
 */
@Experimental
public class KeyStoreTrustAnchorService implements WebAuthnTrustAnchorService {

    private Path keyStore;
    private String password;

    private Set<TrustAnchor> cachedTrustAnchors;

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<TrustAnchor> getTrustAnchors() {

        if(cachedTrustAnchors != null){
            return cachedTrustAnchors;
        }

        KeyStoreTrustAnchorProvider keyStoreTrustAnchorProvider = new KeyStoreTrustAnchorProvider();
        this.cachedTrustAnchors = keyStoreTrustAnchorProvider.provide(getKeyStore(), password);

        return cachedTrustAnchors;
    }

    /**
     * Provides keyStore file
     *
     * @return keyStore file
     */
    public Path getKeyStore() {
        return keyStore;
    }

    /**
     * Sets keyStore file
     *
     * @param keyStore keyStore file
     */
    public void setKeyStore(Path keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Provides keyStore file password
     *
     * @return keyStore file password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets keyStore file password
     *
     * @param password keyStore file password
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
