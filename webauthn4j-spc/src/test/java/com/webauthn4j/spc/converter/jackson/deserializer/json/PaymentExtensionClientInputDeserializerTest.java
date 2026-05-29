package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.AuthenticationExtensionsClientInputsConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentInputs;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PaymentExtensionClientInputDeserializerTest {

    private final ObjectConverter objectConverter = SPCManager.createObjectConverter();
    private final AuthenticationExtensionsClientInputsConverter converter =
            new AuthenticationExtensionsClientInputsConverter(objectConverter);

    @Test
    void deserialize_registration_input() {
        String json = """
                {"payment": {"isPayment": true}}
                """;

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> result = converter.convert(json);

        AuthenticationExtensionsPaymentInputs payment = result.getExtension(AuthenticationExtensionsPaymentInputs.class);
        assertThat(payment).isNotNull();
        assertThat(payment.getIsPayment()).isTrue();
        assertThat(payment.getRpId()).isNull();
    }

    @Test
    void deserialize_authentication_input() {
        String json = """
                {"payment": {
                    "isPayment": true,
                    "rpId": "fancybank.example",
                    "topOrigin": "https://merchant.example",
                    "payeeName": "Merchant Shop",
                    "payeeOrigin": "https://merchant.example",
                    "total": {"currency": "USD", "value": "5.00"},
                    "instrument": {"displayName": "Platinum Card", "icon": "https://icon.png"}
                }}
                """;

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> result = converter.convert(json);

        AuthenticationExtensionsPaymentInputs payment = result.getExtension(AuthenticationExtensionsPaymentInputs.class);
        assertThat(payment).isNotNull();
        assertThat(payment.getIsPayment()).isTrue();
        assertThat(payment.getRpId()).isEqualTo("fancybank.example");
        assertThat(payment.getTopOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(payment.getPayeeName()).isEqualTo("Merchant Shop");
        assertThat(payment.getPayeeOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(payment.getTotal()).isEqualTo(new PaymentCurrencyAmount("USD", "5.00"));
        assertThat(payment.getInstrument().getDisplayName()).isEqualTo("Platinum Card");
    }

    @Test
    void deserialize_null_payment_should_return_null_extension() {
        String json = """
                {"payment": null}
                """;

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> result = converter.convert(json);

        AuthenticationExtensionsPaymentInputs payment = result.getExtension(AuthenticationExtensionsPaymentInputs.class);
        assertThat(payment).isNull();
    }

    @Test
    void deserialize_without_payment_key() {
        String json = """
                {}
                """;

        AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> result = converter.convert(json);

        AuthenticationExtensionsPaymentInputs payment = result.getExtension(AuthenticationExtensionsPaymentInputs.class);
        assertThat(payment).isNull();
    }
}
