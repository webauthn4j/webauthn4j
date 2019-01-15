package com.webauthn4j.validator.attestation.androidkey;

import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Test;

import java.security.cert.X509Certificate;

public class KeyDescriptionValidatorTest {

    private KeyDescriptionValidator keyDescriptionValidator = new KeyDescriptionValidator();

    @Test
    public void validate_test() {
        X509Certificate certificate = TestUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionValidator.validate(certificate, clientDataHash, true);
    }

    @Test
    public void validate_with_teeEnforcedOnly_true_test() {
        X509Certificate certificate = TestUtil.loadAndroidKeyAttestationCertificate();
        byte[] clientDataHash = Base64UrlUtil.decode("aGVsbG8");
        keyDescriptionValidator.validate(certificate, clientDataHash, true);
    }

}
