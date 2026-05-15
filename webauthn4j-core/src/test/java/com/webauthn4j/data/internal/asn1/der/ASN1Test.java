package com.webauthn4j.data.internal.asn1.der;

import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1Test {

    @Test
    void parse_unknown_primitive_returns_ASN1Primitive_test() {
        // NULL → 05 00
        ASN1 parsed = ASN1.parse(new byte[]{0x05, 0x00});
        assertThat(parsed.getClass()).isEqualTo(ASN1Primitive.class);
    }

    @Test
    void parse_context_specific_primitive_returns_ASN1Primitive_test() {
        ASN1 parsed = ASN1.parse(new byte[]{(byte) 0x80, 0x01, 0x00});
        assertThat(parsed.getClass()).isEqualTo(ASN1Primitive.class);
        assertThat(parsed.isConstructed()).isFalse();
    }

    @Test
    void parse_context_specific_constructed_returns_ASN1Structure_test() {
        ASN1 parsed = ASN1.parse(new byte[]{(byte) 0xA0, 0x00});
        assertThat(parsed.getClass()).isEqualTo(ASN1Structure.class);
        assertThat(parsed.isConstructed()).isTrue();
    }

    @Test
    void parse_toBytes_roundtrip_x509_test() throws CertificateEncodingException {
        X509Certificate cert = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate();
        byte[] original = cert.getEncoded();
        assertThat(ASN1.parse(original).toBytes()).isEqualTo(original);
    }
}
