package com.webauthn4j.data.internal.asn1.der;

import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1SequenceTest {

    @Test
    void parse_test() {
        ASN1Sequence parsed = ASN1Sequence.parse(new byte[]{0x30, 0x00});
        assertThat(parsed.size()).isZero();
    }

    @Test
    void parse_x509Certificate_test() throws CertificateEncodingException {
        X509Certificate cert = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate();
        ASN1Sequence parsed = ASN1Sequence.parse(cert.getEncoded());
        assertThat(parsed.size()).isGreaterThan(0);
    }

    @Test
    void create_empty_test() {
        ASN1Sequence seq = ASN1Sequence.create();
        assertThat(seq.isConstructed()).isTrue();
        assertThat(seq.size()).isZero();
        assertThat(seq.toBytes()).containsExactly(0x30, 0x00);
    }

    @Test
    void create_with_children_test() {
        ASN1Sequence seq = ASN1Sequence.create(
                ASN1Integer.create(new byte[]{0x2A}),
                ASN1OctetString.create(new byte[]{0x01, 0x02})
        );
        assertThat(seq.size()).isEqualTo(2);
        assertThat(seq.toBytes()).containsExactly(0x30, 0x07, 0x02, 0x01, 0x2A, 0x04, 0x02, 0x01, 0x02);
    }

    @Test
    void create_nested_test() {
        ASN1Sequence outer = ASN1Sequence.create(
                ASN1Sequence.create(ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03})),
                ASN1BitString.create(new byte[]{0x0A})
        );

        assertThat(outer.size()).isEqualTo(2);

        ASN1Sequence parsed = ASN1Sequence.parse(outer.toBytes());
        assertThat(parsed.size()).isEqualTo(2);
        assertThat(parsed.get(0)).isInstanceOf(ASN1Sequence.class);
        assertThat(parsed.get(1)).isInstanceOf(ASN1BitString.class);
    }

    @Test
    void toBytes_parse_roundtrip_test() {
        ASN1Sequence original = ASN1Sequence.create(
                ASN1Integer.create(new byte[]{0x01}),
                ASN1Sequence.create(ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03})),
                ASN1OctetString.create(new byte[]{(byte) 0xCA, (byte) 0xFE})
        );

        ASN1Sequence parsed = ASN1Sequence.parse(original.toBytes());

        assertThat(parsed.size()).isEqualTo(3);
        assertThat(parsed.toBytes()).isEqualTo(original.toBytes());
    }

    @Test
    void get_test() {
        ASN1Sequence seq = ASN1Sequence.create(
                ASN1Integer.create(new byte[]{0x01}),
                ASN1OctetString.create(new byte[]{0x02})
        );

        assertThat(seq.get(0)).isInstanceOf(ASN1Integer.class);
        assertThat(seq.get(1)).isInstanceOf(ASN1OctetString.class);
    }

    @Test
    void iterator_test() {
        ASN1Sequence seq = ASN1Sequence.create(
                ASN1Integer.create(new byte[]{0x01}),
                ASN1Integer.create(new byte[]{0x02})
        );

        int count = 0;
        for (ASN1 child : seq) {
            assertThat(child).isInstanceOf(ASN1Integer.class);
            count++;
        }
        assertThat(count).isEqualTo(2);
    }

    @Test
    void equals_hashCode_test() {
        ASN1Sequence a = ASN1Sequence.create(ASN1Integer.create(new byte[]{0x01}));
        ASN1Sequence b = ASN1Sequence.create(ASN1Integer.create(new byte[]{0x01}));
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1Sequence a = ASN1Sequence.create(ASN1Integer.create(new byte[]{0x01}));
        ASN1Sequence b = ASN1Sequence.create(ASN1Integer.create(new byte[]{0x02}));
        assertThat(a).isNotEqualTo(b);
    }
}
