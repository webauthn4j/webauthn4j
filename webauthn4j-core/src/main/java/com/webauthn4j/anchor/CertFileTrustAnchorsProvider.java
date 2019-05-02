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
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class CertFileTrustAnchorsProvider extends CachingTrustAnchorsProviderBase {

    // ~ Instance fields
    // ================================================================================================

    private List<Path> certificates;

    // ~ Constructor
    // ========================================================================================================

    public CertFileTrustAnchorsProvider() {
    }

    public CertFileTrustAnchorsProvider(List<Path> certificates) {
        this.certificates = certificates;
    }


    // ~ Methods
    // ========================================================================================================

    private void checkConfig() {
        AssertUtil.notNull(certificates, "certificates must not be null");
    }


    @Override
    protected Map<AAGUID, Set<TrustAnchor>> loadTrustAnchors() {
        checkConfig();
        Set<TrustAnchor> trustAnchors = certificates.stream().map(this::loadTrustAnchor).collect(Collectors.toSet());
        return Collections.singletonMap(AAGUID.NULL, trustAnchors);
    }

    private TrustAnchor loadTrustAnchor(Path certificate) {
        try {
            X509Certificate x509Certificate = CertificateUtil.generateX509Certificate(Files.newInputStream(certificate));
            return new TrustAnchor(x509Certificate, null);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public List<Path> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<Path> certificates) {
        this.certificates = certificates;
    }
}
