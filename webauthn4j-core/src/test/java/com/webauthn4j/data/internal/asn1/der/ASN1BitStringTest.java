package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1BitStringTest {

    @Test
    void create_getValue_includes_unused_bits_prefix_test() {
        ASN1BitString bitString = ASN1BitString.create(new byte[]{0x01, 0x02, 0x03});
        assertThat(bitString.getValue()).containsExactly(0x00, 0x01, 0x02, 0x03);
    }

    @Test
    void create_getContent_strips_unused_bits_prefix_test() {
        ASN1BitString bitString = ASN1BitString.create(new byte[]{0x01, 0x02, 0x03});
        assertThat(bitString.getContent()).containsExactly(0x01, 0x02, 0x03);
    }

    @Test
    void create_toBytes_test() {
        ASN1BitString bitString = ASN1BitString.create(new byte[]{0x0A});
        assertThat(bitString.toBytes()).containsExactly(0x03, 0x02, 0x00, 0x0A);
    }

    @Test
    void toBytes_parse_roundtrip_large_test() {
        byte[] rawBits = new byte[256];
        for (int i = 0; i < rawBits.length; i++) {
            rawBits[i] = (byte) (i & 0xFF);
        }
        ASN1BitString original = ASN1BitString.create(rawBits);
        ASN1BitString parsed = ASN1BitString.parse(original.toBytes());
        assertThat(parsed.getContent()).isEqualTo(rawBits);
    }

    @Test
    void getValue_returns_copy_test() {
        ASN1BitString bitString = ASN1BitString.create(new byte[]{0x0A});
        byte[] value = bitString.getValue();
        value[0] = (byte) 0xFF;
        assertThat(bitString.getValue()[0]).isEqualTo((byte) 0x00);
    }

    @Test
    void equals_hashCode_test() {
        ASN1BitString a = ASN1BitString.create(new byte[]{0x0A});
        ASN1BitString b = ASN1BitString.create(new byte[]{0x0A});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1BitString a = ASN1BitString.create(new byte[]{0x0A});
        ASN1BitString b = ASN1BitString.create(new byte[]{0x0B});
        assertThat(a).isNotEqualTo(b);
    }
}
