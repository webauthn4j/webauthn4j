package com.webauthn4j.spc.data.extension.client;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationExtensionsPaymentInputsTest {

    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    @Test
    void registration_constructor() {
        var browserBoundPubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256));
        var input = new AuthenticationExtensionsPaymentInputs(browserBoundPubKeyCredParams);

        assertThat(input.getIdentifier()).isEqualTo("payment");
        assertThat(input.getValue("payment")).isSameAs(input);
        assertThat(input.getIsPayment()).isTrue();
        assertThat(input.getBrowserBoundPubKeyCredParams()).isEqualTo(browserBoundPubKeyCredParams);
        assertThat(input.getRpId()).isNull();
        assertThat(input.getTopOrigin()).isNull();
        assertThat(input.getTotal()).isNull();
        assertThat(input.getInstrument()).isNull();
        assertThat(input.getPayeeName()).isNull();
        assertThat(input.getPayeeOrigin()).isNull();
        assertThat(input.getPaymentEntitiesLogos()).isNull();
        input.validate();
    }

    @Test
    void registration_constructor_without_bbk() {
        var input = new AuthenticationExtensionsPaymentInputs(null);

        assertThat(input.getIsPayment()).isTrue();
        assertThat(input.getBrowserBoundPubKeyCredParams()).isNull();
    }

    @Test
    void authentication_constructor() {
        var logos = List.of(new PaymentEntityLogo("https://merchant.example/logo.png", "Merchant Shop"));
        var browserBoundPubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256));
        var input = new AuthenticationExtensionsPaymentInputs(
                "fancybank.example", new Origin("https://merchant.example"),
                "Merchant Shop", new Origin("https://merchant.example"),
                logos, TOTAL, INSTRUMENT, browserBoundPubKeyCredParams);

        assertThat(input.getIdentifier()).isEqualTo("payment");
        assertThat(input.getValue("payment")).isSameAs(input);
        assertThat(input.getIsPayment()).isTrue();
        assertThat(input.getRpId()).isEqualTo("fancybank.example");
        assertThat(input.getTopOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(input.getPayeeName()).isEqualTo("Merchant Shop");
        assertThat(input.getPayeeOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(input.getPaymentEntitiesLogos()).isEqualTo(logos);
        assertThat(input.getTotal()).isEqualTo(TOTAL);
        assertThat(input.getInstrument()).isEqualTo(INSTRUMENT);
        assertThat(input.getBrowserBoundPubKeyCredParams()).isEqualTo(browserBoundPubKeyCredParams);
        input.validate();
    }

    @Test
    void getValue_should_throw_for_invalid_key() {
        var input = new AuthenticationExtensionsPaymentInputs(null);
        assertThatThrownBy(() -> input.getValue("invalid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_and_hashCode() {
        var a = new AuthenticationExtensionsPaymentInputs(
                "fancybank.example", new Origin("https://merchant.example"),
                "Merchant", new Origin("https://merchant.example"),
                null, TOTAL, INSTRUMENT, null);
        var b = new AuthenticationExtensionsPaymentInputs(
                "fancybank.example", new Origin("https://merchant.example"),
                "Merchant", new Origin("https://merchant.example"),
                null, TOTAL, INSTRUMENT, null);
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different() {
        var a = new AuthenticationExtensionsPaymentInputs(
                "bank-a.example", new Origin("https://merchant.example"),
                null, null, null, TOTAL, INSTRUMENT, null);
        var b = new AuthenticationExtensionsPaymentInputs(
                "bank-b.example", new Origin("https://merchant.example"),
                null, null, null, TOTAL, INSTRUMENT, null);
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void toString_test() {
        var input = new AuthenticationExtensionsPaymentInputs(null);
        assertThat(input.toString()).isEqualTo("AuthenticationExtensionsPaymentInputs(isPayment=true, browserBoundPubKeyCredParams=null, rpId=null, topOrigin=null, payeeName=null, payeeOrigin=null, paymentEntitiesLogos=null, total=null, instrument=null)");
    }
}
