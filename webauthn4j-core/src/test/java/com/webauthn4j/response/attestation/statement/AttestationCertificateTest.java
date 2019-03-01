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

package com.webauthn4j.response.attestation.statement;

import com.webauthn4j.test.TestUtil;
import com.webauthn4j.validator.exception.CertificateException;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AttestationCertificateTest {

    @Test
    public void getter_test() {
        AttestationCertificate attestationCertificate = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        assertAll(
                () -> assertThat(attestationCertificate.getSubjectCountry()).isEqualTo("JP"),
                () -> assertThat(attestationCertificate.getSubjectOrganization()).isEqualTo("SharpLab."),
                () -> assertThat(attestationCertificate.getSubjectOrganizationUnit()).isEqualTo("Authenticator Attestation"),
                () -> assertThat(attestationCertificate.getSubjectCommonName()).isEqualTo("webauthn4j test 3tier authenticator attestation")
        );
    }

    @Test
    public void validate_test() {
        AttestationCertificate attestationCertificate = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        attestationCertificate.validate();
    }

    @Test
    public void validate_with_invalid_version_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(2); //v2
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void validate_with_invalid_CN_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(3); //v3
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("OU=Authenticator Attestation, O=SharpLab., C=JP"));
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void validate_with_invalid_O_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(3); //v3
        when(certificate.getSubjectX500Principal()).thenReturn(new X500Principal("OU=Authenticator Attestation, CN=webauthn4j test 3tier authenticator attestation, C=JP"));
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void validate_with_invalid_OU_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(3); //v3
        when(certificate.getSubjectX500Principal())
                .thenReturn(new X500Principal("O=SharpLab., CN=webauthn4j test 3tier authenticator attestation, O=SharpLab., C=JP"));
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void validate_with_invalid_C_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(3); //v3
        when(certificate.getSubjectX500Principal())
                .thenReturn(new X500Principal("OU=Authenticator Attestation, O=SharpLab., CN=webauthn4j test 3tier authenticator attestation, O=SharpLab."));
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void validate_with_invalid_basicConstraints_certificate_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getVersion()).thenReturn(3); //v3
        when(certificate.getSubjectX500Principal())
                .thenReturn(new X500Principal("OU=Authenticator Attestation, O=SharpLab., CN=webauthn4j test 3tier authenticator attestation, O=SharpLab., C=JP"));
        AttestationCertificate attestationCertificate = new AttestationCertificate(certificate);
        assertThrows(CertificateException.class,
                () -> attestationCertificate.validate()
        );
    }

    @Test
    public void equals_hashCode_test() {
        AttestationCertificate attestationCertificateA = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        AttestationCertificate attestationCertificateB = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());

        assertAll(
                () -> assertThat(attestationCertificateA).isEqualTo(attestationCertificateB),
                () -> assertThat(attestationCertificateA).hasSameHashCodeAs(attestationCertificateB)
        );
    }

    @Test
    public void getX500Name_with_invalid_subjectDN_test() {
        assertThrows(CertificateException.class,
                () -> AttestationCertificate.getX500Name("Invalid DN")
        );
    }
}
