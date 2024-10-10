package com.webauthn4j.verifier.attestation.statement.androidkey;

import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

class KeyDescriptionVerifierTest {

    private final KeyDescriptionVerifier keyDescriptionVerifier = new KeyDescriptionVerifier();

    @Test
    void verify_test() {
        X509Certificate certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionVerifier.verify(certificate, clientDataHash, false);
    }

    @Test
    void verify_with_teeEnforcedOnly_true_test() {
        X509Certificate certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionVerifier.verify(certificate, clientDataHash, true);
    }
}
