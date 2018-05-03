package com.webauthn4j.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.anchor.WebAuthnTrustAnchorService;
import com.webauthn4j.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.CertificateUtil;
import org.junit.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TrustAnchorCertPathTrustworthinessValidatorTest {

    private WebAuthnTrustAnchorService webAuthnTrustAnchorService = mock(WebAuthnTrustAnchorService.class);
    private TrustAnchorCertPathTrustworthinessValidator target = new TrustAnchorCertPathTrustworthinessValidator(webAuthnTrustAnchorService);

    @Test
    public void validate_test(){

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestUtil.load2tierTestRootCACertificate()));
        when(webAuthnTrustAnchorService.getTrustAnchors()).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestUtil.createFIDOU2FAttestationStatement(TestUtil.create2tierTestAuthenticatorCertPath());
        target.validate(attestationStatement);
    }

}
