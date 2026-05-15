package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1OctetStringTest {

    @Test
    void parse_test() {
        ASN1OctetString parsed = ASN1OctetString.parse(new byte[]{0x04, 0x02, 0x01, 0x02});
        assertThat(parsed.getValue()).containsExactly(0x01, 0x02);
    }

    @Test
    void create_toBytes_test() {
        ASN1OctetString octet = ASN1OctetString.create(new byte[]{0x0A, 0x0B});
        assertThat(octet.toBytes()).containsExactly(0x04, 0x02, 0x0A, 0x0B);
    }

    @Test
    void getValue_test() {
        ASN1OctetString octet = ASN1OctetString.create(new byte[]{0x0A, 0x0B});
        assertThat(octet.getValue()).containsExactly(0x0A, 0x0B);
    }

    @Test
    void getValue_returns_copy_test() {
        ASN1OctetString octet = ASN1OctetString.create(new byte[]{0x0A});
        byte[] value = octet.getValue();
        value[0] = (byte) 0xFF;
        assertThat(octet.getValue()).containsExactly(0x0A);
    }

    @Test
    void equals_hashCode_test() {
        ASN1OctetString a = ASN1OctetString.create(new byte[]{0x0A});
        ASN1OctetString b = ASN1OctetString.create(new byte[]{0x0A});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1OctetString a = ASN1OctetString.create(new byte[]{0x0A});
        ASN1OctetString b = ASN1OctetString.create(new byte[]{0x0B});
        assertThat(a).isNotEqualTo(b);
    }
}
