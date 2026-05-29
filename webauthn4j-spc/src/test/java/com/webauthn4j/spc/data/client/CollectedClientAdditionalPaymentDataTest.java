package com.webauthn4j.spc.data.client;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CollectedClientAdditionalPaymentDataTest {

    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("Card", "https://icon.png");
    private static final COSEKey TEST_KEY = TestDataUtil.createEC2COSEPublicKey();

    @Test
    void constructor_should_create_instance_with_all_fields() {
        List<PaymentEntityLogo> logos = List.of(new PaymentEntityLogo("https://logo.png", "Bank"));
        CollectedClientAdditionalPaymentData data = new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"),
                "Merchant", new Origin("https://merchant.example"),
                logos, TOTAL, INSTRUMENT, TEST_KEY
        );
        assertThat(data.getRpId()).isEqualTo("bank.example");
        assertThat(data.getTopOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(data.getPayeeName()).isEqualTo("Merchant");
        assertThat(data.getPayeeOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(data.getPaymentEntitiesLogos()).hasSize(1);
        assertThat(data.getTotal()).isEqualTo(TOTAL);
        assertThat(data.getInstrument()).isEqualTo(INSTRUMENT);
        assertThat(data.getBrowserBoundPublicKey()).isEqualTo(TEST_KEY);
    }

    @Test
    void constructor_should_allow_optional_fields_to_be_null() {
        CollectedClientAdditionalPaymentData data = new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"),
                null, null, null, TOTAL, INSTRUMENT, null
        );
        assertThat(data.getPayeeName()).isNull();
        assertThat(data.getPayeeOrigin()).isNull();
        assertThat(data.getPaymentEntitiesLogos()).isNull();
        assertThat(data.getBrowserBoundPublicKey()).isNull();
    }

    @Test
    void constructor_should_throw_when_rpId_is_null() {
        assertThatThrownBy(() -> new CollectedClientAdditionalPaymentData(
                null, new Origin("https://merchant.example"), null, null, null, TOTAL, INSTRUMENT, null
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_should_throw_when_total_is_null() {
        assertThatThrownBy(() -> new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"), null, null, null, null, INSTRUMENT, null
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_should_return_true_for_same_values() {
        CollectedClientAdditionalPaymentData a = new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"), "Merchant", null, null, TOTAL, INSTRUMENT, null);
        CollectedClientAdditionalPaymentData b = new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"), "Merchant", null, null, TOTAL, INSTRUMENT, null);
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_rpId() {
        CollectedClientAdditionalPaymentData a = new CollectedClientAdditionalPaymentData(
                "bank.example", new Origin("https://merchant.example"), null, null, null, TOTAL, INSTRUMENT, null);
        CollectedClientAdditionalPaymentData b = new CollectedClientAdditionalPaymentData(
                "other.example", new Origin("https://merchant.example"), null, null, null, TOTAL, INSTRUMENT, null);
        assertThat(a).isNotEqualTo(b);
    }
}
