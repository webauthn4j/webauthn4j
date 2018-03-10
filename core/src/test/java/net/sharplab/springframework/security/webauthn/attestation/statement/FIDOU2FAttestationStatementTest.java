package net.sharplab.springframework.security.webauthn.attestation.statement;

import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;
import org.assertj.core.util.Lists;
import org.junit.Test;

import java.security.cert.CertPath;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for FIDOU2FAttestationStatement
 */
public class FIDOU2FAttestationStatementTest {

    @Test
    public void gettter_setter_test(){
        CertPath certPath = CertificateUtil.generateCertPath(Collections.emptyList());
        byte[] signature = new byte[32];
        FIDOU2FAttestationStatement target = new FIDOU2FAttestationStatement();
        target.setX5c(certPath);
        target.setSig(signature);
        assertThat(target.getX5c()).isEqualTo(certPath);
        assertThat(target.getSig()).isEqualTo(signature);
    }

    @Test
    public void isSelfAttested_test(){
        FIDOU2FAttestationStatement target = CoreTestUtil.createFIDOU2FAttestationStatement();
        assertThat(target.isSelfAttested()).isTrue();
    }

    @Test
    public void isSelfAttested_test_with_multiple_certificates(){
        FIDOU2FAttestationStatement target = CoreTestUtil.createFIDOU2FAttestationStatement();
        target.setX5c(CertificateUtil.generateCertPath(Lists.newArrayList(CoreTestUtil.createFirefoxSWTokenAttestationCertificate(), CoreTestUtil.createFirefoxSWTokenAttestationCertificate())));
        assertThat(target.isSelfAttested()).isFalse();
    }

    @Test
    public void getFormat_test(){
        FIDOU2FAttestationStatement target = CoreTestUtil.createFIDOU2FAttestationStatement();
        assertThat(target.getFormat()).isEqualTo("fido-u2f");
    }

    @Test
    public void getEndEntityCertificate_test(){
        FIDOU2FAttestationStatement target = CoreTestUtil.createFIDOU2FAttestationStatement();
        assertThat(target.getEndEntityCertificate()).isEqualTo(target.getX5c().getCertificates().get(0));
    }

    @Test(expected = IllegalStateException.class)
    public void getEndEntityCertificate_test_with_no_certificates(){
        FIDOU2FAttestationStatement target = CoreTestUtil.createFIDOU2FAttestationStatement();
        target.setX5c(CertificateUtil.generateCertPath(Collections.emptyList()));
        target.getEndEntityCertificate();
    }


    @Test
    public void equals_test(){
        FIDOU2FAttestationStatement instanceA = CoreTestUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = CoreTestUtil.createFIDOU2FAttestationStatement();

        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    public void equals_test_with_not_equal_certificates(){
        FIDOU2FAttestationStatement instanceA = CoreTestUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = CoreTestUtil.createFIDOU2FAttestationStatement();
        instanceB.setX5c(CertificateUtil.generateCertPath(Collections.singletonList(CoreTestUtil.createFeitianU2FTokenAttestationCertificate())));

        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    public void hashCode_test(){
        FIDOU2FAttestationStatement instanceA = CoreTestUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = CoreTestUtil.createFIDOU2FAttestationStatement();

        assertThat(instanceA.hashCode()).isEqualTo(instanceB.hashCode());
    }

    @Test
    public void hashCode_test_with_not_equal_certificates(){
        FIDOU2FAttestationStatement instanceA = CoreTestUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = CoreTestUtil.createFIDOU2FAttestationStatement();
        instanceB.setX5c(CertificateUtil.generateCertPath(Collections.singletonList(CoreTestUtil.createFeitianU2FTokenAttestationCertificate())));

        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }

}
