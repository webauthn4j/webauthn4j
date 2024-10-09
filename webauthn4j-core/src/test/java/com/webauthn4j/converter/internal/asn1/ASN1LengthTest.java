package com.webauthn4j.converter.internal.asn1;

import com.webauthn4j.verifier.internal.asn1.ASN1Length;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ASN1LengthTest {

    @Test
    void getter_test(){
        ASN1Length instance = new ASN1Length(true, 0);
        assertThat(instance.isIndefinite()).isTrue();
        assertThat(instance.getValueLength()).isZero();
    }

    @Test
    void equals_hashCode_test(){
        ASN1Length instanceA = new ASN1Length(false, 8);
        ASN1Length instanceB = new ASN1Length(false, 8);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }
}
