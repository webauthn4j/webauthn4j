package com.webauthn4j.spc.data.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PaymentCurrencyAmountTest {

    @Test
    void constructor_should_create_instance() {
        PaymentCurrencyAmount amount = new PaymentCurrencyAmount("USD", "5.00");
        assertThat(amount.getCurrency()).isEqualTo("USD");
        assertThat(amount.getValue()).isEqualTo("5.00");
    }

    @Test
    void constructor_should_throw_when_currency_is_null() {
        assertThatThrownBy(() -> new PaymentCurrencyAmount(null, "5.00"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_should_throw_when_value_is_null() {
        assertThatThrownBy(() -> new PaymentCurrencyAmount("USD", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_should_return_true_for_same_values() {
        PaymentCurrencyAmount a = new PaymentCurrencyAmount("USD", "5.00");
        PaymentCurrencyAmount b = new PaymentCurrencyAmount("USD", "5.00");
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_values() {
        PaymentCurrencyAmount a = new PaymentCurrencyAmount("USD", "5.00");
        PaymentCurrencyAmount b = new PaymentCurrencyAmount("EUR", "5.00");
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void toString_test() {
        PaymentCurrencyAmount amount = new PaymentCurrencyAmount("USD", "5.00");
        assertThat(amount.toString()).isEqualTo("PaymentCurrencyAmount(currency=USD, value=5.00)");
    }
}
