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
import com.webauthn4j.util.AssertUtil;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class TrustAnchorResolverImpl implements TrustAnchorResolver {

    private TrustAnchorProvider trustAnchorProvider;

    public TrustAnchorResolverImpl(TrustAnchorProvider trustAnchorProvider) {
        this.trustAnchorProvider = trustAnchorProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<TrustAnchor> resolve(AAGUID aaguid) {
        AssertUtil.notNull(aaguid, "aaguid must not be null");

        Map<AAGUID, Set<TrustAnchor>> trustAnchors = trustAnchorProvider.provide();

        HashSet<TrustAnchor> set = new HashSet<>();
        set.addAll(trustAnchors.getOrDefault(AAGUID.NULL, Collections.emptySet()));
        set.addAll(trustAnchors.getOrDefault(aaguid, Collections.emptySet()));
        return set;
    }


}
