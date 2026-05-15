package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1IntegerTest {

    @Test
    void parse_test() {
        ASN1Integer parsed = ASN1Integer.parse(new byte[]{0x02, 0x01, 0x2A});
        assertThat(parsed.getContent()).isEqualTo(BigInteger.valueOf(42));
    }

    @Test
    void create_toBytes_test() {
        ASN1Integer integer = ASN1Integer.create(new byte[]{0x2A});
        assertThat(integer.toBytes()).containsExactly(0x02, 0x01, 0x2A);
    }

    @Test
    void getContent_test() {
        ASN1Integer integer = ASN1Integer.create(new byte[]{0x00, (byte) 0xFF});
        assertThat(integer.getContent()).isEqualTo(BigInteger.valueOf(255));
    }

    @Test
    void toBytes_parse_roundtrip_test() {
        ASN1Integer original = ASN1Integer.create(new byte[]{0x00, (byte) 0xFF});
        ASN1Integer parsed = ASN1Integer.parse(original.toBytes());
        assertThat(parsed.getValue()).isEqualTo(original.getValue());
    }

    @Test
    void getValue_returns_copy_test() {
        ASN1Integer integer = ASN1Integer.create(new byte[]{0x2A});
        byte[] value = integer.getValue();
        value[0] = (byte) 0xFF;
        assertThat(integer.getValue()).containsExactly(0x2A);
    }

    @Test
    void equals_hashCode_test() {
        ASN1Integer a = ASN1Integer.create(new byte[]{0x2A});
        ASN1Integer b = ASN1Integer.create(new byte[]{0x2A});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1Integer a = ASN1Integer.create(new byte[]{0x2A});
        ASN1Integer b = ASN1Integer.create(new byte[]{0x2B});
        assertThat(a).isNotEqualTo(b);
    }
}
