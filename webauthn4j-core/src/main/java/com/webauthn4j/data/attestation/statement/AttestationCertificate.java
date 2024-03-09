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

import com.webauthn4j.validator.exception.CertificateException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;


public class AttestationCertificate {

    private static final int CERTIFICATE_VERSION_3 = 3;
    private static final int NON_CA = -1;
    private final X509Certificate certificate;

    public AttestationCertificate(@NonNull X509Certificate certificate) {
        this.certificate = certificate;
    }

    private static Map<String, Object> toMap(Rdn rdn) {
        try {
            Map<String, Object> map = new HashMap<>();
            Attributes attributes = rdn.toAttributes();
            NamingEnumeration<String> ids = rdn.toAttributes().getIDs();

            while (ids.hasMore()) {
                String id = ids.next();
                map.put(id, attributes.get(id).get());
            }
            return map;

        } catch (NamingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public @NonNull X509Certificate getCertificate() {
        return certificate;
    }

    public @Nullable String getSubjectCountry() {
        return getValue("C");
    }

    public @Nullable String getSubjectOrganization() {
        return getValue("O");
    }

    public @Nullable String getSubjectOrganizationUnit() {
        return getValue("OU");
    }

    public @Nullable String getSubjectCommonName() {
        return getValue("CN");
    }

    public void validate() {
        if (certificate.getVersion() != CERTIFICATE_VERSION_3) {
            throw new CertificateException("Attestation certificate must be version 3");
        }

        String country = getSubjectCountry();
        if (country == null || country.isEmpty()) {
            throw new CertificateException("Subject-C must be present");
        }
        String organization = getSubjectOrganization();
        if (organization == null || organization.isEmpty()) {
            throw new CertificateException("Subject-O must be present");
        }
        String organizationUnit = getSubjectOrganizationUnit();
        if (organizationUnit == null || !organizationUnit.equals("Authenticator Attestation")) {
            throw new CertificateException("Subject-OU must be present");
        }
        String commonName = getSubjectCommonName();
        if (commonName == null || commonName.isEmpty()) {
            throw new CertificateException("Subject-CN must be present");
        }

        if (certificate.getBasicConstraints() != NON_CA) {
            throw new CertificateException("Attestation certificate must not be CA certificate");
        }
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttestationCertificate that = (AttestationCertificate) o;
        return Objects.equals(certificate, that.certificate);
    }

    @Override
    public int hashCode() {

        return Objects.hash(certificate);
    }

    @Nullable String getValue(@NonNull String name) {
        try {
            LdapName subjectDN = new LdapName(getCertificate().getSubjectX500Principal().getName());
            Map<String, Object> map = subjectDN.getRdns().stream().flatMap(rdn -> toMap(rdn).entrySet().stream()).collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            return (String) map.get(name);
        } catch (InvalidNameException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
