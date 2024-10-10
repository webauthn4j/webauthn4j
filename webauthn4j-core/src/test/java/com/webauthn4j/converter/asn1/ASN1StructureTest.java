package com.webauthn4j.converter.asn1;

import com.webauthn4j.verifier.internal.asn1.ASN1Structure;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;

class ASN1StructureTest {

    @Test
    void can_parse_x509Certificate() {
        X509Certificate attestationCertificate = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate();
        assertThatCode(()-> ASN1Structure.parse(attestationCertificate.getEncoded())).doesNotThrowAnyException();
    }

}