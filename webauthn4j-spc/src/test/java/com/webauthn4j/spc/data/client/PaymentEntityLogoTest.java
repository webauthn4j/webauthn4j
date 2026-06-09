package com.webauthn4j.spc.data.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PaymentEntityLogoTest {

    @Test
    void constructor_should_create_instance() {
        PaymentEntityLogo logo = new PaymentEntityLogo("https://bank.example/logo.png", "Fancy Bank");
        assertThat(logo.getUrl()).isEqualTo("https://bank.example/logo.png");
        assertThat(logo.getLabel()).isEqualTo("Fancy Bank");
    }

    @Test
    void constructor_should_throw_when_url_is_null() {
        assertThatThrownBy(() -> new PaymentEntityLogo(null, "label"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_should_return_true_for_same_values() {
        PaymentEntityLogo a = new PaymentEntityLogo("https://logo.png", "Bank");
        PaymentEntityLogo b = new PaymentEntityLogo("https://logo.png", "Bank");
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_values() {
        PaymentEntityLogo a = new PaymentEntityLogo("https://logo1.png", "Bank");
        PaymentEntityLogo b = new PaymentEntityLogo("https://logo2.png", "Bank");
        assertThat(a).isNotEqualTo(b);
    }
}
