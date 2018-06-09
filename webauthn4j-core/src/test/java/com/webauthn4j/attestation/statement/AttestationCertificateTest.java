package com.webauthn4j.attestation.statement;

import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationCertificateTest {

    @Test
    public void getter_test(){
        AttestationCertificate attestationCertificate = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        assertThat(attestationCertificate.getSubjectCountry()).isEqualTo("JP");
        assertThat(attestationCertificate.getSubjectOrganization()).isEqualTo("SharpLab.");
        assertThat(attestationCertificate.getSubjectOrganizationUnit()).isEqualTo("Authenticator Attestation");
        assertThat(attestationCertificate.getSubjectCommonName()).isEqualTo("webauthn4j test 3tier authenticator attestation");
    }

    @Test
    public void validate_test(){
        AttestationCertificate attestationCertificate = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        attestationCertificate.validate();
    }

    @Test
    public void equals_hashCode_test() {
        AttestationCertificate attestationCertificateA = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());
        AttestationCertificate attestationCertificateB = new AttestationCertificate(TestUtil.load3tierTestAuthenticatorAttestationCertificate());

        assertThat(attestationCertificateA).isEqualTo(attestationCertificateB);
        assertThat(attestationCertificateA).hasSameHashCodeAs(attestationCertificateB);

    }
}
