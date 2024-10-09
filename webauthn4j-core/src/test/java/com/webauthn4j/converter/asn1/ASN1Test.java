package com.webauthn4j.converter.asn1;

import com.webauthn4j.converter.internal.asn1.ASN1;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;

class ASN1Test {

    @Test
    void can_parse_x509Certificate() {
        X509Certificate attestationCertificate = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate();
        assertThatCode(()-> ASN1.parse(attestationCertificate.getEncoded())).doesNotThrowAnyException();
    }

}