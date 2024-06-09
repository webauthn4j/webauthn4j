package com.webauthn4j.verifier.attestation.statement.androidkey;

import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.spy;

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

    @Test
    void verify_with_IOException_test() throws IOException {
        KeyDescriptionVerifier target = spy(KeyDescriptionVerifier.class);
        doThrow(new IOException()).when(target).extractKeyDescription(any());
        X509Certificate x509Certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        assertThrows(UncheckedIOException.class,
                () -> target.verify(x509Certificate, new byte[32], false)
        );
    }
}
