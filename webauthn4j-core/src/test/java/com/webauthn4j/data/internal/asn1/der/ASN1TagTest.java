package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1TagTest {

    @Test
    void getter_test() {
        ASN1Tag instance = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, true, 0x10);
        assertThat(instance.getTagClass()).isEqualTo(ASN1Tag.ASN1TagClass.UNIVERSAL);
        assertThat(instance.isConstructed()).isTrue();
        assertThat(instance.getNumber()).isEqualTo(0x10);
    }

    @Test
    void equals_hashCode_test() {
        ASN1Tag instanceA = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, 0x03);
        ASN1Tag instanceB = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, 0x03);
        assertThat(instanceA).isEqualTo(instanceB).hasSameHashCodeAs(instanceB);
    }

    @Test
    void toBytes_sequence_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, true, ASN1Tag.SEQUENCE);
        assertThat(tag.toBytes()).containsExactly(0x30);
    }

    @Test
    void toBytes_integer_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.INTEGER);
        assertThat(tag.toBytes()).containsExactly(0x02);
    }

    @Test
    void toBytes_bit_string_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.BIT_STRING);
        assertThat(tag.toBytes()).containsExactly(0x03);
    }

    @Test
    void toBytes_octet_string_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.OCTET_STRING);
        assertThat(tag.toBytes()).containsExactly(0x04);
    }

    @Test
    void toBytes_object_identifier_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, ASN1Tag.OBJECT_IDENTIFIER);
        assertThat(tag.toBytes()).containsExactly(0x06);
    }

    @Test
    void toBytes_context_specific_test() {
        ASN1Tag tag = new ASN1Tag(ASN1Tag.ASN1TagClass.CONTEXT_SPECIFIC, true, 0);
        assertThat(tag.toBytes()).containsExactly(0xA0);
    }

    @Test
    void toBytes_parse_roundtrip_short_form_test() {
        ASN1Tag original = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, true, ASN1Tag.SEQUENCE);
        ASN1Tag parsed = ASN1Tag.parse(ByteBuffer.wrap(original.toBytes()));
        assertThat(parsed).isEqualTo(original);
    }

    @Test
    void toBytes_parse_roundtrip_long_form_test() {
        ASN1Tag original = new ASN1Tag(ASN1Tag.ASN1TagClass.CONTEXT_SPECIFIC, false, 31);
        ASN1Tag parsed = ASN1Tag.parse(ByteBuffer.wrap(original.toBytes()));
        assertThat(parsed).isEqualTo(original);
    }

    @Test
    void toBytes_parse_roundtrip_large_tag_number_test() {
        ASN1Tag original = new ASN1Tag(ASN1Tag.ASN1TagClass.CONTEXT_SPECIFIC, true, 200);
        ASN1Tag parsed = ASN1Tag.parse(ByteBuffer.wrap(original.toBytes()));
        assertThat(parsed).isEqualTo(original);
    }
}
