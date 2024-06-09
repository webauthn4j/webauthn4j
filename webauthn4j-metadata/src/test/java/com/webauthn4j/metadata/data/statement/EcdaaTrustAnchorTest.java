package com.webauthn4j.metadata.data.statement;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EcdaaTrustAnchorTest {

    @Test
    void constructor_test(){
        EcdaaTrustAnchor ecdaaTrustAnchor = new EcdaaTrustAnchor("xDummy", "yDummy", "cDummy", "sxDummy", "syDummy", "g1CurveDummy");
        assertThat(ecdaaTrustAnchor.getX()).isEqualTo("xDummy");
        assertThat(ecdaaTrustAnchor.getY()).isEqualTo("yDummy");
        assertThat(ecdaaTrustAnchor.getC()).isEqualTo("cDummy");
        assertThat(ecdaaTrustAnchor.getSx()).isEqualTo("sxDummy");
        assertThat(ecdaaTrustAnchor.getSy()).isEqualTo("syDummy");
        assertThat(ecdaaTrustAnchor.getG1Curve()).isEqualTo("g1CurveDummy");
    }

    @Test
    void equals_hashCode_test(){
        EcdaaTrustAnchor instanceA = new EcdaaTrustAnchor("xDummy", "yDummy", "cDummy", "sxDummy", "syDummy", "g1CurveDummy");
        EcdaaTrustAnchor instanceB = new EcdaaTrustAnchor("xDummy", "yDummy", "cDummy", "sxDummy", "syDummy", "g1CurveDummy");
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

}