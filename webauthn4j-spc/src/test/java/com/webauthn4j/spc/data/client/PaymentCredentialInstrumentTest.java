package com.webauthn4j.spc.data.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PaymentCredentialInstrumentTest {

    @Test
    void constructor_with_all_fields() {
        PaymentCredentialInstrument instrument = new PaymentCredentialInstrument(
                "Platinum Card", "https://bank.example/icon.png", false, "****1234");
        assertThat(instrument.getDisplayName()).isEqualTo("Platinum Card");
        assertThat(instrument.getIcon()).isEqualTo("https://bank.example/icon.png");
        assertThat(instrument.getIconMustBeShown()).isFalse();
        assertThat(instrument.getDetails()).isEqualTo("****1234");
    }

    @Test
    void constructor_with_defaults() {
        PaymentCredentialInstrument instrument = new PaymentCredentialInstrument(
                "Platinum Card", "https://bank.example/icon.png");
        assertThat(instrument.getIconMustBeShown()).isNull();
        assertThat(instrument.getDetails()).isNull();
    }

    @Test
    void equals_should_return_true_for_same_values() {
        PaymentCredentialInstrument a = new PaymentCredentialInstrument(
                "Card", "https://icon.png", true, "details");
        PaymentCredentialInstrument b = new PaymentCredentialInstrument(
                "Card", "https://icon.png", true, "details");
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_displayName() {
        PaymentCredentialInstrument a = new PaymentCredentialInstrument("Card A", "https://icon.png");
        PaymentCredentialInstrument b = new PaymentCredentialInstrument("Card B", "https://icon.png");
        assertThat(a).isNotEqualTo(b);
    }
}
