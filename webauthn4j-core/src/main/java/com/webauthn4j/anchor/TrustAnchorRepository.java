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

import com.webauthn4j.data.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Repository interface that look up {@link TrustAnchor}(s)
 * WebAuthn4J uses this interface to lookup {@link TrustAnchor}(s) for an attestation certificate when verifying the authenticator.
 */
public interface TrustAnchorRepository {

    /**
     * Look up {@link TrustAnchor}(s) by {@link AAGUID}
     * @param aaguid {@link AAGUID} for the authenticator
     * @return {@link Set<TrustAnchor>}
     */
    Set<TrustAnchor> find(AAGUID aaguid);

    /**
     * Look up {@link TrustAnchor}(s) by attestationCertificateKeyIdentifier. This is used for FIDO-U2F authenticator
     * @param attestationCertificateKeyIdentifier attestationCertificateKeyIdentifier for the authenticator
     * @return {@link Set<TrustAnchor>}
     */
    Set<TrustAnchor> find(byte[] attestationCertificateKeyIdentifier);
}
