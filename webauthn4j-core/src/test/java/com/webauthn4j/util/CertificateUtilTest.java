package com.webauthn4j.util;

import com.webauthn4j.test.CoreTestUtil;
import org.junit.Test;

import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class CertificateUtilTest {

    @Test
    public void generateCertPathValidator_test(){
        CertPathValidator certPathValidator = CertificateUtil.createCertPathValidator();
        assertThat(certPathValidator).isNotNull();
    }

    @Test
    public void createPKIXParameters_test(){
        HashSet<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(CoreTestUtil.loadTestRootCACertificate(), null));
        PKIXParameters pkixParameters = CertificateUtil.createPKIXParameters(trustAnchors);
        assertThat(pkixParameters).isNotNull();
    }

    @Test
    public void createPKIXParameters_test_with_empty_trustAnchors(){
        HashSet<TrustAnchor> trustAnchors = new HashSet<>();
        assertThatThrownBy(()->{
                CertificateUtil.createPKIXParameters(trustAnchors);
        }).isInstanceOf(IllegalArgumentException.class).hasMessage("trustAnchors is required; it must not be empty");
    }

    @Test
    public void createKeystore_test(){
        CertificateUtil.createKeyStore();
    }

}
