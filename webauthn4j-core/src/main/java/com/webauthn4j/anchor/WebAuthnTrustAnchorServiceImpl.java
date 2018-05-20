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

import com.webauthn4j.util.AssertUtil;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * KeyStore backed TrustAnchorService
 * Load a key store at first time access and cache it.
 */
public class WebAuthnTrustAnchorServiceImpl implements WebAuthnTrustAnchorService {

    private final TrustAnchorProvider trustAnchorProvider;
    private Set<TrustAnchor> cachedTrustAnchors;

    public WebAuthnTrustAnchorServiceImpl(TrustAnchorProvider trustAnchorProvider) {
        AssertUtil.notNull(trustAnchorProvider, "trustAnchorProvider must not be null");
        this.trustAnchorProvider = trustAnchorProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<TrustAnchor> getTrustAnchors() {

        if (cachedTrustAnchors != null) {
            return cachedTrustAnchors;
        }

        this.cachedTrustAnchors = trustAnchorProvider.provide();

        return cachedTrustAnchors;
    }

}
