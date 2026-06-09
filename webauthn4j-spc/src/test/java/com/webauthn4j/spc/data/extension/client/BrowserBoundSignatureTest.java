package com.webauthn4j.spc.data.extension.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BrowserBoundSignatureTest {

    @Test
    void constructor_and_getter() {
        byte[] sig = {1, 2, 3};
        var bbs = new BrowserBoundSignature(sig);
        assertThat(bbs.getSignature()).isEqualTo(sig);
    }

    @Test
    void getSignature_returns_copy() {
        byte[] sig = {1, 2, 3};
        var bbs = new BrowserBoundSignature(sig);
        bbs.getSignature()[0] = 99;
        assertThat(bbs.getSignature()[0]).isEqualTo((byte) 1);
    }

    @Test
    void constructor_should_throw_when_null() {
        assertThatThrownBy(() -> new BrowserBoundSignature(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_and_hashCode() {
        var a = new BrowserBoundSignature(new byte[]{1, 2, 3});
        var b = new BrowserBoundSignature(new byte[]{1, 2, 3});
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different() {
        var a = new BrowserBoundSignature(new byte[]{1, 2, 3});
        var b = new BrowserBoundSignature(new byte[]{4, 5, 6});
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void toString_test() {
        var bbs = new BrowserBoundSignature(new byte[]{1, 2});
        assertThat(bbs.toString()).isEqualTo("BrowserBoundSignature(signature=0102)");
    }
}
