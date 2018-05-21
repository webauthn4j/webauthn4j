package com.webauthn4j.attestation.statement;

import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationCertificatePathTest {

    @Test
    public void getEndEntityCertificate_test() {
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(TestUtil.create2tierTestAuthenticatorCertPath());
        assertThat(attestationCertificatePath.getEndEntityAttestationCertificate()).isEqualTo(attestationCertificatePath.getEndEntityAttestationCertificate());
    }

    @Test(expected = IllegalStateException.class)
    public void getEndEntityCertificate_test_with_no_certificates() {
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath();
        attestationCertificatePath.getEndEntityAttestationCertificate();
    }
}
