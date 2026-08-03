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

import com.webauthn4j.data.internal.asn1.der.ASN1;
import com.webauthn4j.data.internal.asn1.der.ASN1ObjectIdentifier;
import com.webauthn4j.data.internal.asn1.der.ASN1Primitive;
import com.webauthn4j.data.internal.asn1.der.ASN1Structure;
import com.webauthn4j.data.internal.asn1.der.ASN1Utf8String;
import com.webauthn4j.verifier.exception.CertificateException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;


public class AttestationCertificate {

    private static final int CERTIFICATE_VERSION_3 = 3;
    private static final int NON_CA = -1;

    private static final String OID_CN = "2.5.4.3";
    private static final String OID_C = "2.5.4.6";
    private static final String OID_O = "2.5.4.10";
    private static final String OID_OU = "2.5.4.11";

    private static final int ASN1_TAG_UTF8_STRING = 0x0C;

    private static final Map<String, String> NAME_TO_OID = Map.of(
            "CN", OID_CN,
            "C", OID_C,
            "O", OID_O,
            "OU", OID_OU
    );

    private final X509Certificate certificate;

    public AttestationCertificate(@NotNull X509Certificate certificate) {
        this.certificate = certificate;
    }

    public @NotNull X509Certificate getCertificate() {
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
        //spec| Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).
        if (certificate.getVersion() != CERTIFICATE_VERSION_3) {
            throw new CertificateException("Attestation certificate must be version 3", certificate);
        }

        //spec| Subject field MUST be set to:
        //spec| Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)
        String country = getSubjectCountry();
        if (country == null || country.isEmpty()) {
            throw new CertificateException("Subject-C must be present", certificate);
        }
        //spec| Subject-O: Legal name of the Authenticator vendor (UTF8String)
        String organization = getSubjectOrganization();
        if (organization == null || organization.isEmpty()) {
            throw new CertificateException("Subject-O must be present", certificate);
        }
        //spec| Subject-OU: Literal string "Authenticator Attestation" (UTF8String)
        String organizationUnit = getSubjectOrganizationUnit();
        if (organizationUnit == null || !organizationUnit.equals("Authenticator Attestation")) {
            throw new CertificateException("Subject-OU must be present", certificate);
        }
        //spec| Subject-CN: A UTF8String of the vendor's choosing
        String commonName = getSubjectCommonName();
        if (commonName == null || commonName.isEmpty()) {
            throw new CertificateException("Subject-CN must be present", certificate);
        }

        //spec| The Basic Constraints extension MUST have the CA component set to false.
        if (certificate.getBasicConstraints() != NON_CA) {
            throw new CertificateException("Attestation certificate must not be CA certificate", certificate);
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

    @Nullable String getValue(@NotNull String name) {
        String oid = NAME_TO_OID.get(name);
        if (oid == null) {
            return null;
        }
        byte[] encoded = certificate.getSubjectX500Principal().getEncoded();
        Map<String, String> attributes = parseRdnSequence(encoded);
        return attributes.get(oid);
    }

    private static Map<String, String> parseRdnSequence(byte[] encoded) {
        Map<String, String> attributes = new HashMap<>();
        ASN1Structure rdnSequence = (ASN1Structure) ASN1.parse(encoded);

        for (ASN1 rdnElement : rdnSequence) {
            ASN1Structure rdn = (ASN1Structure) rdnElement;
            for (ASN1 attrElement : rdn) {
                ASN1Structure attributeTypeAndValue = (ASN1Structure) attrElement;
                ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.parse(attributeTypeAndValue.get(0).toBytes());
                ASN1 value = attributeTypeAndValue.get(1);
                attributes.put(oid.getContent(), decodeStringValue(value));
            }
        }
        return attributes;
    }

    private static String decodeStringValue(ASN1 value) {
        int tagNumber = value.getTagNumber();
        if (tagNumber == ASN1_TAG_UTF8_STRING) {
            return ASN1Utf8String.parse(value.toBytes()).getContent();
        }
        return new String(((ASN1Primitive) value).getValue(), StandardCharsets.US_ASCII);
    }
}
