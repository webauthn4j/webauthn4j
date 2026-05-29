package com.webauthn4j.spc.converter.jackson.serializer.json;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.client.CollectedClientAdditionalPaymentRegistrationData;
import com.webauthn4j.spc.data.client.CollectedClientPaymentData;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class COSEKeyBase64UrlSerializerTest {

    private final ObjectConverter objectConverter = SPCManager.createObjectConverter();

    @Test
    void serialize_then_deserialize_should_roundtrip() {
        EC2COSEKey key = TestDataUtil.createEC2COSEPublicKey();
        CollectedClientPaymentData original = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE,
                new DefaultChallenge(),
                new Origin("https://bank.example"),
                null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(key)
        );

        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        byte[] serialized = converter.convertToBytes(original);
        CollectedClientData deserialized = converter.convert(serialized);

        CollectedClientPaymentData result = (CollectedClientPaymentData) deserialized;
        assertThat(result.getPayment().getBrowserBoundPublicKey()).isEqualTo(key);
    }

    @Test
    void serialize_should_produce_json_with_base64url_string() {
        EC2COSEKey key = TestDataUtil.createEC2COSEPublicKey();
        CollectedClientPaymentData data = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE,
                new DefaultChallenge(),
                new Origin("https://bank.example"),
                null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(key)
        );

        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        byte[] json = converter.convertToBytes(data);
        String jsonString = new String(json);

        assertThat(jsonString).contains("\"browserBoundPublicKey\":\"");
    }

    @Test
    void serialize_null_browserBoundPublicKey_should_omit_field() {
        CollectedClientPaymentData data = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE,
                new DefaultChallenge(),
                new Origin("https://bank.example"),
                null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(null)
        );

        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        byte[] json = converter.convertToBytes(data);
        CollectedClientData deserialized = converter.convert(json);

        CollectedClientPaymentData result = (CollectedClientPaymentData) deserialized;
        assertThat(result.getPayment().getBrowserBoundPublicKey()).isNull();
    }
}
