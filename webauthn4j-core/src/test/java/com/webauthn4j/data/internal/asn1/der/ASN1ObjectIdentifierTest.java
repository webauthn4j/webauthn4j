package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1ObjectIdentifierTest {

    @Test
    void parse_test() {
        ASN1ObjectIdentifier parsed = ASN1ObjectIdentifier.parse(new byte[]{0x06, 0x03, 0x55, 0x04, 0x03});
        assertThat(parsed.getValue()).containsExactly(0x55, 0x04, 0x03);
    }

    @Test
    void create_toBytes_test() {
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03});
        assertThat(oid.toBytes()).containsExactly(0x06, 0x03, 0x55, 0x04, 0x03);
    }

    @Test
    void getContent_test() {
        // OID 2.5.4.3 (commonName)
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03});
        assertThat(oid.getContent()).isEqualTo("2.5.4.3");
    }

    @Test
    void getContent_long_oid_test() {
        // OID 1.2.840.113635.100.8.2 (Apple nonce extension)
        // 1*40+2=42=0x2A, 840=0x86 0x48, 113635=0x86 0xF7 0x63, 100=0x64, 8=0x08, 2=0x02
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.create(new byte[]{
                0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x63, 0x64, 0x08, 0x02
        });
        assertThat(oid.getContent()).isEqualTo("1.2.840.113635.100.8.2");
    }

    @Test
    void getContent_oid_starting_with_2_test() {
        // OID 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
        ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.create(new byte[]{
                0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
        });
        assertThat(oid.getContent()).isEqualTo("2.16.840.1.101.3.4.3.18");
    }

    @Test
    void equals_hashCode_test() {
        ASN1ObjectIdentifier a = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03});
        ASN1ObjectIdentifier b = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1ObjectIdentifier a = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x03});
        ASN1ObjectIdentifier b = ASN1ObjectIdentifier.create(new byte[]{0x55, 0x04, 0x04});
        assertThat(a).isNotEqualTo(b);
    }
}
