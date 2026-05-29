package com.webauthn4j.spc.verifier;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.converter.jackson.SPCJSONModule;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.SPCAuthenticationParameters;
import com.webauthn4j.spc.data.client.*;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SPCAuthenticationVerifierTest {

    private final SPCAuthenticationVerifier target = new SPCAuthenticationVerifier();
    private final ObjectConverter objectConverter = createObjectConverter();

    private static ObjectConverter createObjectConverter() {
        return SPCManager.createObjectConverter();
    }

    private static final String RP_ID = "fancybank.example";
    private static final Origin MERCHANT_ORIGIN = new Origin("https://merchant.example");
    private static final PaymentCurrencyAmount TOTAL = new PaymentCurrencyAmount("USD", "5.00");
    private static final PaymentCredentialInstrument INSTRUMENT =
            new PaymentCredentialInstrument("FancyBank Platinum Card", "https://fancybank.example/card-art.png");

    // --- verifyRpId ---

    @Test
    void verifyRpId_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyRpId(RP_ID, RP_ID)).doesNotThrowAnyException();
    }

    @Test
    void verifyRpId_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyRpId("wrong.example", RP_ID))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("rpId");
    }

    // --- verifyTopOrigin ---

    @Test
    void verifyTopOrigin_should_succeed_when_matching() {
        OriginPredicate predicate = buildTopOriginPredicate(MERCHANT_ORIGIN);
        assertThatCode(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), predicate))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyTopOrigin_should_throw_when_not_matching() {
        OriginPredicate predicate = buildTopOriginPredicate(new Origin("https://other.example"));
        assertThatThrownBy(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), predicate))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("topOrigin");
    }

    @Test
    void verifyTopOrigin_should_throw_when_predicate_is_not_configured() {
        assertThatThrownBy(() -> target.verifyTopOrigin(new Origin("https://merchant.example"), null))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("topOriginPredicate must be configured");
    }

    // --- verifyTotal ---

    @Test
    void verifyTotal_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyTotal(TOTAL, TOTAL)).doesNotThrowAnyException();
    }

    @Test
    void verifyTotal_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyTotal(new PaymentCurrencyAmount("USD", "10.00"), TOTAL))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("total");
    }

    // --- verifyInstrument ---

    @Test
    void verifyInstrument_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyInstrument(INSTRUMENT, INSTRUMENT)).doesNotThrowAnyException();
    }

    @Test
    void verifyInstrument_should_throw_when_not_matching() {
        PaymentCredentialInstrument wrong = new PaymentCredentialInstrument("Other Card", "https://other.example/icon.png");
        assertThatThrownBy(() -> target.verifyInstrument(wrong, INSTRUMENT))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("instrument");
    }

    // --- verifyPayeeName ---

    @Test
    void verifyPayeeName_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyPayeeName("Merchant Shop", "Merchant Shop")).doesNotThrowAnyException();
    }

    @Test
    void verifyPayeeName_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyPayeeName("Evil Shop", "Merchant Shop"))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("payeeName");
    }

    @Test
    void verifyPayeeName_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPayeeName("Any Name", null)).doesNotThrowAnyException();
    }

    // --- verifyPayeeOrigin ---

    @Test
    void verifyPayeeOrigin_should_succeed_when_matching() {
        assertThatCode(() -> target.verifyPayeeOrigin(new Origin("https://merchant.example"), new Origin("https://merchant.example"))).doesNotThrowAnyException();
    }

    @Test
    void verifyPayeeOrigin_should_throw_when_not_matching() {
        assertThatThrownBy(() -> target.verifyPayeeOrigin(new Origin("https://evil.example"), new Origin("https://merchant.example")))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("payeeOrigin");
    }

    @Test
    void verifyPayeeOrigin_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPayeeOrigin(new Origin("https://any.example"), null)).doesNotThrowAnyException();
    }

    // --- verifyPaymentEntitiesLogos ---

    @Test
    void verifyPaymentEntitiesLogos_should_succeed_when_ordered_subset() {
        PaymentEntityLogo logoA = new PaymentEntityLogo("https://a.png", "A");
        PaymentEntityLogo logoB = new PaymentEntityLogo("https://b.png", "B");
        PaymentEntityLogo logoC = new PaymentEntityLogo("https://c.png", "C");
        assertThatCode(() -> target.verifyPaymentEntitiesLogos(List.of(logoA, logoC), List.of(logoA, logoB, logoC)))
                .doesNotThrowAnyException();
    }

    @Test
    void verifyPaymentEntitiesLogos_should_throw_when_not_ordered_subset() {
        PaymentEntityLogo logoA = new PaymentEntityLogo("https://a.png", "A");
        PaymentEntityLogo logoB = new PaymentEntityLogo("https://b.png", "B");
        PaymentEntityLogo logoC = new PaymentEntityLogo("https://c.png", "C");
        assertThatThrownBy(() -> target.verifyPaymentEntitiesLogos(List.of(logoC, logoA), List.of(logoA, logoB, logoC)))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("paymentEntitiesLogos");
    }

    @Test
    void verifyPaymentEntitiesLogos_should_skip_when_expected_is_null() {
        assertThatCode(() -> target.verifyPaymentEntitiesLogos(null, null)).doesNotThrowAnyException();
    }

    // --- verify (integration) ---

    @Test
    void verify_should_succeed_with_matching_payment_data() {
        AuthenticationObject authObject = createAuthenticationObject(
                RP_ID, TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"), null,
                createParams(TOTAL, INSTRUMENT, "Merchant Shop", new Origin("https://merchant.example"))
        );
        assertThatCode(() -> target.verify(authObject)).doesNotThrowAnyException();
    }

    @Test
    void verify_should_throw_when_not_SPCAuthenticationParameters() {
        CollectedClientData plainClientData = TestDataUtil.createClientData(ClientDataType.WEBAUTHN_GET);
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(plainClientData);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(objectConverter).convert(authenticatorData);
        AuthenticationParameters authenticationParameters = new AuthenticationParameters(createServerProperty(), TestDataUtil.createCredentialRecord(), null, false, true);
        AuthenticationObject plainObject = new AuthenticationObject(
                new byte[32], authenticatorData, authenticatorDataBytes,
                plainClientData, clientDataBytes, new AuthenticationExtensionsClientOutputs<>(),
                authenticationParameters
        );
        assertThatThrownBy(() -> target.verify(plainObject))
                .isInstanceOf(ConstraintViolationException.class)
                .hasMessageContaining("SPCAuthenticationParameters");
    }

    // --- helpers ---

    private SPCAuthenticationParameters createParams(
            PaymentCurrencyAmount total, PaymentCredentialInstrument instrument,
            String payeeName, Origin payeeOrigin) {
        return new SPCAuthenticationParameters(
                createServerProperty(), TestDataUtil.createCredentialRecord(),
                total, instrument, payeeName, payeeOrigin
        );
    }

    private static OriginPredicate buildTopOriginPredicate(Origin topOrigin) {
        return ServerProperty.builder()
                .origin(MERCHANT_ORIGIN).rpId(RP_ID).challenge(new DefaultChallenge())
                .topOrigin(topOrigin).build().getTopOriginPredicate();
    }

    private ServerProperty createServerProperty() {
        return ServerProperty.builder()
                .origin(MERCHANT_ORIGIN).rpId(RP_ID).challenge(new DefaultChallenge())
                .topOrigin(MERCHANT_ORIGIN).build();
    }

    private AuthenticationObject createAuthenticationObject(
            String rpId, PaymentCurrencyAmount total, PaymentCredentialInstrument instrument,
            String payeeName, Origin payeeOrigin, List<PaymentEntityLogo> logos,
            SPCAuthenticationParameters params) {
        CollectedClientPaymentData clientData = new CollectedClientPaymentData(
                ClientDataType.create("payment.get"),
                new DefaultChallenge(),
                MERCHANT_ORIGIN,
                true, MERCHANT_ORIGIN, null,
                new CollectedClientAdditionalPaymentData(
                        rpId, new Origin("https://merchant.example"),
                        payeeName, payeeOrigin, logos,
                        total, instrument, null
                )
        );
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(clientData);
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(objectConverter).convert(authenticatorData);
        return new AuthenticationObject(
                new byte[32], authenticatorData, authenticatorDataBytes,
                clientData, clientDataBytes, new AuthenticationExtensionsClientOutputs<>(),
                params
        );
    }
}
