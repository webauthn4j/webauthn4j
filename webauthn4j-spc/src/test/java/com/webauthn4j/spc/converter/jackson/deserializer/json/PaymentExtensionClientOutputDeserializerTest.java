package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.extension.client.AuthenticationExtensionsPaymentOutputs;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PaymentExtensionClientOutputDeserializerTest {

    private final ObjectConverter objectConverter = SPCManager.createObjectConverter();
    private final AuthenticationExtensionsClientOutputsConverter converter =
            new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    @Test
    void deserialize_with_browserBoundSignature() {
        byte[] signatureBytes = new byte[]{1, 2, 3, 4, 5};
        String signatureBase64Url = Base64UrlUtil.encodeToString(signatureBytes);
        String json = """
                {"payment": {"browserBoundSignature": {"signature": "%s"}}}
                """.formatted(signatureBase64Url);

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> result = converter.convert(json);

        AuthenticationExtensionsPaymentOutputs payment = result.getExtension(AuthenticationExtensionsPaymentOutputs.class);
        assertThat(payment).isNotNull();
        assertThat(payment.getBrowserBoundSignature()).isNotNull();
        assertThat(payment.getBrowserBoundSignature().getSignature()).isEqualTo(signatureBytes);
    }

    @Test
    void deserialize_without_browserBoundSignature() {
        String json = """
                {"payment": {}}
                """;

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> result = converter.convert(json);

        AuthenticationExtensionsPaymentOutputs payment = result.getExtension(AuthenticationExtensionsPaymentOutputs.class);
        assertThat(payment).isNotNull();
        assertThat(payment.getBrowserBoundSignature()).isNull();
    }

    @Test
    void deserialize_null_payment_should_return_null_extension() {
        String json = """
                {"payment": null}
                """;

        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> result = converter.convert(json);

        AuthenticationExtensionsPaymentOutputs payment = result.getExtension(AuthenticationExtensionsPaymentOutputs.class);
        assertThat(payment).isNull();
    }
}
