package com.webauthn4j.spc.data;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurePaymentConfirmationRequestTest {

    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    @Test
    void constructor_and_getters() {
        var challenge = new DefaultChallenge();
        var credentialIds = List.of(new byte[]{1, 2, 3});
        var logos = List.of(new PaymentEntityLogo("https://fancybank.example/logo.png", "FancyBank"));
        var extensions = new AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>();
        var browserBoundPubKeyCredParams = List.of(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256));

        var request = new SecurePaymentConfirmationRequest(
                challenge, "fancybank.example", credentialIds, INSTRUMENT,
                60000L, "Merchant Shop", new Origin("https://merchant.example"),
                logos, extensions, browserBoundPubKeyCredParams, List.of("en"), true);

        assertThat(request.getChallenge()).isEqualTo(challenge);
        assertThat(request.getRpId()).isEqualTo("fancybank.example");
        assertThat(request.getCredentialIds()).hasSize(1);
        assertThat(request.getInstrument()).isEqualTo(INSTRUMENT);
        assertThat(request.getTimeout()).isEqualTo(60000L);
        assertThat(request.getPayeeName()).isEqualTo("Merchant Shop");
        assertThat(request.getPayeeOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(request.getPaymentEntitiesLogos()).isEqualTo(logos);
        assertThat(request.getExtensions()).isEqualTo(extensions);
        assertThat(request.getBrowserBoundPubKeyCredParams()).isEqualTo(browserBoundPubKeyCredParams);
        assertThat(request.getLocale()).containsExactly("en");
        assertThat(request.getShowOptOut()).isTrue();
    }

    @Test
    void constructor_with_minimal_fields() {
        var request = new SecurePaymentConfirmationRequest(
                new DefaultChallenge(), "fancybank.example",
                List.of(new byte[]{1}), INSTRUMENT,
                null, null, null, null, null, null, null, null);

        assertThat(request.getTimeout()).isNull();
        assertThat(request.getPayeeName()).isNull();
        assertThat(request.getPayeeOrigin()).isNull();
        assertThat(request.getPaymentEntitiesLogos()).isNull();
        assertThat(request.getExtensions()).isNull();
        assertThat(request.getBrowserBoundPubKeyCredParams()).isNull();
        assertThat(request.getLocale()).isNull();
        assertThat(request.getShowOptOut()).isNull();
    }

    @Test
    void constructor_should_throw_when_challenge_is_null() {
        assertThatThrownBy(() -> new SecurePaymentConfirmationRequest(
                null, "rp", List.of(), INSTRUMENT,
                null, null, null, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_should_throw_when_rpId_is_null() {
        assertThatThrownBy(() -> new SecurePaymentConfirmationRequest(
                new DefaultChallenge(), null, List.of(), INSTRUMENT,
                null, null, null, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_should_throw_when_credentialIds_is_null() {
        assertThatThrownBy(() -> new SecurePaymentConfirmationRequest(
                new DefaultChallenge(), "rp", null, INSTRUMENT,
                null, null, null, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_and_hashCode() {
        var challenge = new DefaultChallenge();
        var credentialIds = List.of(new byte[]{1, 2, 3});
        var a = new SecurePaymentConfirmationRequest(
                challenge, "fancybank.example", credentialIds, INSTRUMENT,
                60000L, "Merchant", new Origin("https://merchant.example"),
                null, null, null, null, null);
        var b = new SecurePaymentConfirmationRequest(
                challenge, "fancybank.example", credentialIds, INSTRUMENT,
                60000L, "Merchant", new Origin("https://merchant.example"),
                null, null, null, null, null);
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_rpId() {
        var challenge = new DefaultChallenge();
        var a = new SecurePaymentConfirmationRequest(
                challenge, "bank-a.example", List.of(new byte[]{1}), INSTRUMENT,
                null, null, null, null, null, null, null, null);
        var b = new SecurePaymentConfirmationRequest(
                challenge, "bank-b.example", List.of(new byte[]{1}), INSTRUMENT,
                null, null, null, null, null, null, null, null);
        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void toString_test() {
        var challenge = new DefaultChallenge();
        var request = new SecurePaymentConfirmationRequest(
                challenge, "fancybank.example", List.of(new byte[]{1}), INSTRUMENT,
                60000L, "Merchant", new Origin("https://merchant.example"),
                null, null, null, null, null);
        assertThat(request.toString())
                .contains("fancybank.example")
                .contains("Merchant")
                .contains("60000");
    }

    @Test
    void constructor_should_throw_when_instrument_is_null() {
        assertThatThrownBy(() -> new SecurePaymentConfirmationRequest(
                new DefaultChallenge(), "rp", List.of(), null,
                null, null, null, null, null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
