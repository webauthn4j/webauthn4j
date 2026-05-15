package com.webauthn4j.data.internal.asn1.der;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1Utf8StringTest {

    @Test
    void getContent_test() {
        // UTF8String "Hello" → 0C 05 48 65 6C 6C 6F
        ASN1Utf8String utf8 = ASN1Utf8String.parse(new byte[]{0x0C, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F});
        assertThat(utf8.getContent()).isEqualTo("Hello");
    }

    @Test
    void equals_hashCode_test() {
        ASN1Utf8String a = ASN1Utf8String.parse(new byte[]{0x0C, 0x02, 0x48, 0x69});
        ASN1Utf8String b = ASN1Utf8String.parse(new byte[]{0x0C, 0x02, 0x48, 0x69});
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void not_equals_test() {
        ASN1Utf8String a = ASN1Utf8String.parse(new byte[]{0x0C, 0x02, 0x48, 0x69});
        ASN1Utf8String b = ASN1Utf8String.parse(new byte[]{0x0C, 0x02, 0x48, 0x6F});
        assertThat(a).isNotEqualTo(b);
    }
}
