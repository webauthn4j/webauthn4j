/*
 * Copyright 2018 the original author or authors.
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
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.cert.TrustAnchor;
import java.util.Map;
import java.util.Set;

/**
 * An abstract {@link TrustAnchorsProvider} implementation that provides caching functionality
 * @deprecated
 */
@Deprecated
public abstract class CachingTrustAnchorsProviderBase implements TrustAnchorsProvider {

    // ~ Instance fields
    // ================================================================================================

    private Map<AAGUID, Set<TrustAnchor>> cachedTrustAnchors;

    // ~ Methods
    // ========================================================================================================

    /**
     * Loads {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map} and cache it.
     *
     * @return {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map}
     */
    @Override
    public @NonNull Map<AAGUID, Set<TrustAnchor>> provide() {
        if (cachedTrustAnchors == null) {
            synchronized (this) {
                cachedTrustAnchors = loadTrustAnchors();
            }
        }
        return cachedTrustAnchors;
    }

    /**
     * Loads {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map}
     *
     * @return {@link AAGUID} key {@link TrustAnchor} {@link Set} value {@link Map}
     */
    protected abstract @NonNull Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors();
}
