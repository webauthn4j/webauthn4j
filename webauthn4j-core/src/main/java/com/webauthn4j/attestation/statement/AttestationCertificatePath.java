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

package com.webauthn4j.attestation.statement;

import com.webauthn4j.util.CertificateUtil;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AttestationCertificatePath extends ArrayList<X509Certificate> {

    public AttestationCertificatePath(List<X509Certificate> certificates) {
        this.addAll(certificates);
    }

    public AttestationCertificatePath() {
    }

    public CertPath createCertPath() {
        return CertificateUtil.generateCertPath(new ArrayList<>(this));
    }

    public AttestationCertificate getEndEntityAttestationCertificate() {
        if (this.isEmpty()) {
            throw new IllegalStateException();
        }
        return new AttestationCertificate(this.get(0));
    }
}
