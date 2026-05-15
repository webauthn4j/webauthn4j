package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ASN1LengthTest {

    @Test
    void getter_test() {
        ASN1Length instance = new ASN1Length(8);
        assertThat(instance.getValueLength()).isEqualTo(8);
    }

    @Test
    void toBytes_short_form_test() {
        assertThat(new ASN1Length(5).toBytes()).containsExactly(0x05);
    }

    @Test
    void toBytes_short_form_max_test() {
        assertThat(new ASN1Length(127).toBytes()).containsExactly(0x7F);
    }

    @Test
    void toBytes_long_form_one_byte_test() {
        assertThat(new ASN1Length(128).toBytes()).containsExactly((byte) 0x81, (byte) 0x80);
    }

    @Test
    void toBytes_long_form_one_byte_255_test() {
        assertThat(new ASN1Length(255).toBytes()).containsExactly((byte) 0x81, (byte) 0xFF);
    }

    @Test
    void toBytes_long_form_two_bytes_test() {
        assertThat(new ASN1Length(256).toBytes()).containsExactly((byte) 0x82, (byte) 0x01, (byte) 0x00);
    }

    @Test
    void toBytes_long_form_two_bytes_1952_test() {
        assertThat(new ASN1Length(1952).toBytes()).containsExactly((byte) 0x82, (byte) 0x07, (byte) 0xA0);
    }

    @Test
    void parse_indefinite_length_throws_test() {
        byte[] data = {(byte) 0x80};
        assertThatThrownBy(() -> ASN1Length.parse(ByteBuffer.wrap(data)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Indefinite length is not allowed in DER");
    }

    @Test
    void toBytes_parse_roundtrip_short_form_test() {
        ASN1Length original = new ASN1Length(42);
        ASN1Length parsed = ASN1Length.parse(ByteBuffer.wrap(original.toBytes()));
        assertThat(parsed.getValueLength()).isEqualTo(42);
    }

    @Test
    void toBytes_parse_roundtrip_long_form_test() {
        ASN1Length original = new ASN1Length(1952);
        ASN1Length parsed = ASN1Length.parse(ByteBuffer.wrap(original.toBytes()));
        assertThat(parsed.getValueLength()).isEqualTo(1952);
    }
}
