package com.webauthn4j.validator.attestation.statement.androidkey;

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

class KeyDescriptionValidatorTest {

    private final KeyDescriptionValidator keyDescriptionValidator = new KeyDescriptionValidator();

    @Test
    void validate_test() {
        X509Certificate certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionValidator.validate(certificate, clientDataHash, false);
    }

    @Test
    void validate_with_teeEnforcedOnly_true_test() {
        X509Certificate certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionValidator.validate(certificate, clientDataHash, true);
    }

    @Test
    void validate_with_IOException_test() throws IOException {
        KeyDescriptionValidator target = spy(KeyDescriptionValidator.class);
        doThrow(new IOException()).when(target).extractKeyDescription(any());
        X509Certificate x509Certificate = TestAttestationUtil.loadAndroidKeyAttestationCertificate();
        assertThrows(UncheckedIOException.class,
                () -> target.validate(x509Certificate, new byte[32], false)
        );
    }
}
