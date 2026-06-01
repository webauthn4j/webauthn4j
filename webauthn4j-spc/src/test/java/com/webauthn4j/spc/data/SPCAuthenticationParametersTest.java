package com.webauthn4j.spc.data;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.credential.BrowserBoundKey;
import com.webauthn4j.spc.credential.SPCCredentialRecord;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.test.TestDataUtil;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SPCAuthenticationParametersTest {

    private static final ServerProperty SERVER_PROPERTY = ServerProperty.builder()
            .origin(new Origin("https://merchant.example")).rpId("fancybank.example")
            .challenge(new DefaultChallenge()).topOrigin(new Origin("https://merchant.example")).build();
    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    @Test
    void constructor_with_all_params() {
        var logos = List.of(new PaymentEntityLogo("https://merchant.example/logo.png", "Merchant"));
        var allowCredentials = List.of(new byte[]{1, 2, 3});
        var params = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(), allowCredentials,
                false, true,
                TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"), logos);

        assertThat(params.getServerProperty()).isEqualTo(SERVER_PROPERTY);
        assertThat(params.getExpectedTotal()).isEqualTo(TOTAL);
        assertThat(params.getExpectedInstrument()).isEqualTo(INSTRUMENT);
        assertThat(params.getExpectedPayeeName()).isEqualTo("Merchant Shop");
        assertThat(params.getExpectedPayeeOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(params.getExpectedPaymentEntitiesLogos()).isEqualTo(logos);
        assertThat(params.isUserVerificationRequired()).isFalse();
        assertThat(params.isUserPresenceRequired()).isTrue();
    }

    @Test
    void constructor_with_minimal_params() {
        var params = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                TOTAL, INSTRUMENT, null, null);

        assertThat(params.getExpectedTotal()).isEqualTo(TOTAL);
        assertThat(params.getExpectedInstrument()).isEqualTo(INSTRUMENT);
        assertThat(params.getExpectedPayeeName()).isNull();
        assertThat(params.getExpectedPayeeOrigin()).isNull();
        assertThat(params.getExpectedPaymentEntitiesLogos()).isNull();
    }

    @Test
    void constructor_should_throw_when_total_is_null() {
        assertThatThrownBy(() -> new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                null, INSTRUMENT, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructor_should_throw_when_instrument_is_null() {
        assertThatThrownBy(() -> new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                TOTAL, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_should_return_true_for_same_values() {
        var a = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                TOTAL, INSTRUMENT, "Merchant", new Origin("https://merchant.example"));
        var b = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                TOTAL, INSTRUMENT, "Merchant", new Origin("https://merchant.example"));
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_total() {
        var a = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                TOTAL, INSTRUMENT, null, null);
        var b = new SPCAuthenticationParameters(
                SERVER_PROPERTY, createSPCCredentialRecord(),
                new PaymentCurrencyAmount("EUR", "10.00"), INSTRUMENT, null, null);
        assertThat(a).isNotEqualTo(b);
    }

    private static SPCCredentialRecord createSPCCredentialRecord() {
        CredentialRecord base = TestDataUtil.createCredentialRecord();
        return new TestSPCCredentialRecord(base, Collections.emptyList());
    }

    private static class TestSPCCredentialRecord extends CredentialRecordImpl implements SPCCredentialRecord {
        private final List<BrowserBoundKey> browserBoundKeys;

        TestSPCCredentialRecord(CredentialRecord base, List<BrowserBoundKey> browserBoundKeys) {
            super(
                    base.getAttestationStatement(),
                    base.isUvInitialized(),
                    base.isBackupEligible(),
                    base.isBackedUp(),
                    base.getCounter(),
                    base.getAttestedCredentialData(),
                    base.getAuthenticatorExtensions(),
                    base.getClientData(),
                    base.getClientExtensions(),
                    base.getTransports()
            );
            this.browserBoundKeys = browserBoundKeys;
        }

        @Override
        public @NotNull List<BrowserBoundKey> getBrowserBoundKeys() {
            return browserBoundKeys;
        }
    }
}
