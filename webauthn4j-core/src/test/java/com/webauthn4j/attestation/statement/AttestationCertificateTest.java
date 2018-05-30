package com.webauthn4j.attestation.statement;

import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationCertificateTest {

    @Test
    public void equals_hashCode_test(){
        AttestationCertificate attestationCertificateA = new AttestationCertificate(TestUtil.load2tierTestAuthenticatorAttestationCertificate());
        AttestationCertificate attestationCertificateB = new AttestationCertificate(TestUtil.load2tierTestAuthenticatorAttestationCertificate());

        assertThat(attestationCertificateA).isEqualTo(attestationCertificateB);
        assertThat(attestationCertificateA).hasSameHashCodeAs(attestationCertificateB);

    }
}
