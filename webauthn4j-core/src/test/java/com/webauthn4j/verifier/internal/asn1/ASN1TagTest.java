package com.webauthn4j.verifier.internal.asn1;


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1TagTest {

    @Test
    void getter_test(){
        ASN1Tag instance = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, true, 0x10);
        assertThat(instance.getTagClass()).isEqualTo(ASN1Tag.ASN1TagClass.UNIVERSAL);
        assertThat(instance.isConstructed()).isTrue();
        assertThat(instance.getNumber()).isEqualTo(0x10);
    }

    @Test
    void equals_hashCode_test(){
        ASN1Tag instanceA = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, 0x03);
        ASN1Tag instanceB = new ASN1Tag(ASN1Tag.ASN1TagClass.UNIVERSAL, false, 0x03);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }


}