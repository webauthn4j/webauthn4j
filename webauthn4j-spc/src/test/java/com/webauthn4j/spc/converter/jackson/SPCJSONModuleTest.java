package com.webauthn4j.spc.converter.jackson;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.jackson.serializer.cbor.EC2COSEKeySerializer;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.client.*;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.module.SimpleModule;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class SPCJSONModuleTest {

    private static ObjectConverter createObjectConverter() {
        return SPCManager.createObjectConverter();
    }

    @Test
    void deserialize_authentication_clientDataJSON_should_return_CollectedClientPaymentData() {
        String json = """
                {
                    "type": "payment.get",
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "origin": "https://merchant.example",
                    "crossOrigin": true,
                    "topOrigin": "https://merchant.example",
                    "payment": {
                        "rpId": "fancybank.example",
                        "topOrigin": "https://merchant.example",
                        "payeeName": "Merchant Shop",
                        "payeeOrigin": "https://merchant.example",
                        "total": {
                            "currency": "USD",
                            "value": "5.00"
                        },
                        "instrument": {
                            "displayName": "FancyBank Platinum Card",
                            "icon": "https://fancybank.example/card-art.png"
                        }
                    }
                }
                """;

        ObjectConverter objectConverter = createObjectConverter();
        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData result = converter.convert(json.getBytes(StandardCharsets.UTF_8));

        assertThat(result).isInstanceOf(CollectedClientPaymentData.class);
        CollectedClientPaymentData paymentData = (CollectedClientPaymentData) result;
        assertThat(paymentData.getType()).isEqualTo(ClientDataType.create("payment.get"));
        assertThat(paymentData.getPayment()).isInstanceOf(CollectedClientAdditionalPaymentData.class);

        CollectedClientAdditionalPaymentData payment = (CollectedClientAdditionalPaymentData) paymentData.getPayment();
        assertThat(payment.getRpId()).isEqualTo("fancybank.example");
        assertThat(payment.getTopOrigin()).isEqualTo(new Origin("https://merchant.example"));
        assertThat(payment.getPayeeName()).isEqualTo("Merchant Shop");
        assertThat(payment.getTotal().getCurrency()).isEqualTo("USD");
        assertThat(payment.getTotal().getValue()).isEqualTo("5.00");
        assertThat(payment.getInstrument().getDisplayName()).isEqualTo("FancyBank Platinum Card");
    }

    @Test
    void deserialize_registration_clientDataJSON_should_return_CollectedClientPaymentData() {
        // Create a real COSEKey, serialize to CBOR, then base64url-encode for JSON
        COSEKey expectedKey = TestDataUtil.createEC2COSEPublicKey();
        CBORMapper cborMapperForKey = CBORMapper.builder()
                .addModule(new SimpleModule().addSerializer(new EC2COSEKeySerializer()))
                .build();
        byte[] cborBytes = cborMapperForKey.writeValueAsBytes(expectedKey);
        String base64UrlKey = Base64UrlUtil.encodeToString(cborBytes);

        String json = """
                {
                    "type": "webauthn.create",
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "origin": "https://bank.example",
                    "payment": {
                        "browserBoundPublicKey": "%s"
                    }
                }
                """.formatted(base64UrlKey);

        ObjectConverter objectConverter = createObjectConverter();
        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData result = converter.convert(json.getBytes(StandardCharsets.UTF_8));

        assertThat(result).isInstanceOf(CollectedClientPaymentData.class);
        CollectedClientPaymentData paymentData = (CollectedClientPaymentData) result;
        assertThat(paymentData.getType()).isEqualTo(ClientDataType.WEBAUTHN_CREATE);
        assertThat(paymentData.getPayment()).isInstanceOf(CollectedClientAdditionalPaymentRegistrationData.class);
        assertThat(paymentData.getPayment().getBrowserBoundPublicKey()).isEqualTo(expectedKey);
    }

    @Test
    void serialize_then_deserialize_should_roundtrip_authentication_data() {
        ObjectConverter objectConverter = createObjectConverter();
        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);

        CollectedClientPaymentData original = new CollectedClientPaymentData(
                ClientDataType.create("payment.get"),
                new DefaultChallenge(),
                new Origin("https://merchant.example"),
                true, new Origin("https://merchant.example"), null,
                new CollectedClientAdditionalPaymentData(
                        "fancybank.example", new Origin("https://merchant.example"),
                        "Merchant Shop", new Origin("https://merchant.example"),
                        null,
                        new PaymentCurrencyAmount("USD", "5.00"),
                        new PaymentCredentialInstrument("Platinum Card", "https://icon.png"),
                        null
                )
        );

        byte[] serialized = converter.convertToBytes(original);
        CollectedClientData deserialized = converter.convert(serialized);

        assertThat(deserialized).isInstanceOf(CollectedClientPaymentData.class);
        CollectedClientPaymentData result = (CollectedClientPaymentData) deserialized;
        assertThat(result.getType()).isEqualTo(original.getType());
        assertThat(result.getChallenge()).isEqualTo(original.getChallenge());
        assertThat(result.getOrigin()).isEqualTo(original.getOrigin());

        CollectedClientAdditionalPaymentData payment = (CollectedClientAdditionalPaymentData) result.getPayment();
        assertThat(payment.getRpId()).isEqualTo("fancybank.example");
        assertThat(payment.getTotal()).isEqualTo(new PaymentCurrencyAmount("USD", "5.00"));
        assertThat(payment.getInstrument().getDisplayName()).isEqualTo("Platinum Card");
    }

    @Test
    void deserialize_without_payment_field_should_return_CollectedClientData() {
        String json = """
                {
                    "type": "webauthn.get",
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "origin": "https://example.com"
                }
                """;

        ObjectConverter objectConverter = createObjectConverter();
        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData result = converter.convert(json.getBytes(StandardCharsets.UTF_8));

        assertThat(result).isNotInstanceOf(CollectedClientPaymentData.class)
                .isInstanceOf(CollectedClientData.class);
        assertThat(result.getType()).isEqualTo(ClientDataType.WEBAUTHN_GET);
    }
}
