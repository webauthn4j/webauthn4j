package com.webauthn4j.util;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SignatureUtilTest {

    @Test
    public void createSignature_test(){
        SignatureUtil.createSignature("SHA256withRSA");
    }

    @Test
    public void createSignature_test_with_null(){
        assertThatThrownBy(()->{
            SignatureUtil.createSignature(null);
        }).isInstanceOf(IllegalArgumentException.class).hasMessage("algorithm is required; it must not be null");
    }

    @Test
    public void createSignature_test_with_illegal_argument(){
        assertThatThrownBy(()->{
            SignatureUtil.createSignature("dummyAlg");
        }).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("dummyAlg Signature not available");
    }
}
