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

package com.webauthn4j.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.anchor.TrustAnchorsResolver;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.util.AssertUtil;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Validates the specified {@link AttestationStatement} x5c trustworthiness based on {@link TrustAnchor}
 */
public class TrustAnchorCertPathTrustworthinessValidator extends CertPathTrustworthinessValidatorBase {

    private final TrustAnchorsResolver trustAnchorsResolver;

    public TrustAnchorCertPathTrustworthinessValidator(TrustAnchorsResolver trustAnchorsResolver) {
        AssertUtil.notNull(trustAnchorsResolver, "trustAnchorsResolver must not be null");
        this.trustAnchorsResolver = trustAnchorsResolver;
    }

    @Override
    protected Set<TrustAnchor> resolveTrustAnchors(AAGUID aaguid) {
        return trustAnchorsResolver.resolve(aaguid);
    }
}
