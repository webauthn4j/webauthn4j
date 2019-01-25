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

import com.webauthn4j.response.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Map;
import java.util.Set;

public abstract class CachingTrustAnchorProviderBase implements TrustAnchorProvider {

    private Map<AAGUID, Set<TrustAnchor>> cachedTrustAnchors;

    /**
     * validate aaguid {@link TrustAnchor} {@link Set} map backed by Java KeyStore file.
     *
     * @return aaguid {@link TrustAnchor} {@link Set} map
     */
    @Override
    public Map<AAGUID, Set<TrustAnchor>> provide() {
        if (cachedTrustAnchors == null) {
            cachedTrustAnchors = loadTrustAnchors();
        }
        return cachedTrustAnchors;
    }

    protected abstract Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors();
}
