package com.webauthn4j.spc.data.extension.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationExtensionsPaymentOutputsTest {

    @Test
    void getIdentifier() {
        var output = new AuthenticationExtensionsPaymentOutputs(null);
        assertThat(output.getIdentifier()).isEqualTo("payment");
    }

    @Test
    void getBrowserBoundSignature() {
        var sig = new BrowserBoundSignature(new byte[]{1, 2, 3});
        var output = new AuthenticationExtensionsPaymentOutputs(sig);
        assertThat(output.getBrowserBoundSignature()).isEqualTo(sig);
    }

    @Test
    void getBrowserBoundSignature_returns_null_when_not_set() {
        var output = new AuthenticationExtensionsPaymentOutputs(null);
        assertThat(output.getBrowserBoundSignature()).isNull();
    }

    @Test
    void getValue() {
        var sig = new BrowserBoundSignature(new byte[]{1});
        var output = new AuthenticationExtensionsPaymentOutputs(sig);
        assertThat(output.getValue("payment")).isEqualTo(sig);
    }

    @Test
    void getValue_should_throw_for_invalid_key() {
        var output = new AuthenticationExtensionsPaymentOutputs(null);
        assertThatThrownBy(() -> output.getValue("invalid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validate_should_not_throw() {
        var output = new AuthenticationExtensionsPaymentOutputs(null);
        output.validate();
    }

    @Test
    void equals_and_hashCode() {
        var sig = new BrowserBoundSignature(new byte[]{1});
        var a = new AuthenticationExtensionsPaymentOutputs(sig);
        var b = new AuthenticationExtensionsPaymentOutputs(sig);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different() {
        var a = new AuthenticationExtensionsPaymentOutputs(new BrowserBoundSignature(new byte[]{1}));
        var b = new AuthenticationExtensionsPaymentOutputs(new BrowserBoundSignature(new byte[]{2}));
        assertThat(a).isNotEqualTo(b);
    }
}
