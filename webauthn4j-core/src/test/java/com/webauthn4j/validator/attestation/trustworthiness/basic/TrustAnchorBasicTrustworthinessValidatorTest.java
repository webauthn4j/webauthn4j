package com.webauthn4j.validator.attestation.trustworthiness.basic;

import com.webauthn4j.anchor.WebAuthnTrustAnchorService;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.CertificateUtil;
import org.junit.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.Set;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TrustAnchorBasicTrustworthinessValidatorTest {

    private WebAuthnTrustAnchorService webAuthnTrustAnchorService = mock(WebAuthnTrustAnchorService.class);
    private TrustAnchorBasicTrustworthinessValidator target = new TrustAnchorBasicTrustworthinessValidator(webAuthnTrustAnchorService);

    @Test
    public void validate_test(){

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestUtil.load2tierTestRootCACertificate()));
        when(webAuthnTrustAnchorService.getTrustAnchors()).thenReturn(trustAnchors);

        AttestationStatement attestationStatement = TestUtil.createFIDOU2FAttestationStatement(TestUtil.create2tierTestAuthenticatorCertPath());
        target.validate(attestationStatement);
    }
    
}
