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

package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CertificateUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.*;

public class AttestationCertificatePath extends AbstractList<X509Certificate> {

    private final int size;
    private final X509Certificate[] certificates;

    @JsonCreator
    public AttestationCertificatePath(@NonNull List<X509Certificate> certificates) {
        AssertUtil.notNull(certificates, "certificates must not be null");
        this.size = certificates.size();
        this.certificates = certificates.toArray(new X509Certificate[this.size]);
    }

    public AttestationCertificatePath(@NonNull X509Certificate attestationCertificate, @NonNull List<X509Certificate> caCertificates) {
        AssertUtil.notNull(attestationCertificate, "attestationCertificate must not be null");
        AssertUtil.notNull(caCertificates, "caCertificates must not be null");
        List<X509Certificate> buffer = new ArrayList<>();
        buffer.add(attestationCertificate);
        buffer.addAll(caCertificates);
        this.size = buffer.size();
        this.certificates = buffer.toArray(new X509Certificate[this.size]);
    }

    public AttestationCertificatePath() {
        this(Collections.emptyList());
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public @NonNull X509Certificate get(int index) {
        return certificates[index];
    }

    public @NonNull CertPath createCertPath() {
        return CertificateUtil.generateCertPath(this);
    }

    public @NonNull AttestationCertificate getEndEntityAttestationCertificate() {
        if (this.isEmpty()) {
            throw new IllegalStateException();
        }
        return new AttestationCertificate(this.get(0));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AttestationCertificatePath that = (AttestationCertificatePath) o;
        return size == that.size &&
                Arrays.equals(certificates, that.certificates);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(super.hashCode(), size);
        result = 31 * result + Arrays.hashCode(certificates);
        return result;
    }

    @Override
    public String toString() {
        return "AttestationCertificatePath(" +
                ", certificates=" + Arrays.deepToString(Arrays.stream(certificates).map(cert -> "[" + cert.getSubjectX500Principal().toString() + "]").toArray()) +
                ')';
    }
}
