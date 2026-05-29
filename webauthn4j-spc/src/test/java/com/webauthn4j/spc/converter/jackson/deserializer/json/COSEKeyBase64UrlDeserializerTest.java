package com.webauthn4j.spc.converter.jackson.deserializer.json;

import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.spc.SPCManager;
import com.webauthn4j.spc.data.client.CollectedClientAdditionalPaymentRegistrationData;
import com.webauthn4j.spc.data.client.CollectedClientPaymentData;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class COSEKeyBase64UrlDeserializerTest {

    private final ObjectConverter objectConverter = SPCManager.createObjectConverter();

    @Test
    void deserialize_should_parse_base64url_encoded_cose_key() {
        EC2COSEKey expectedKey = TestDataUtil.createEC2COSEPublicKey();
        byte[] cborBytes = objectConverter.getCborMapper().writeValueAsBytes(expectedKey);
        String base64Url = Base64UrlUtil.encodeToString(cborBytes);

        String json = """
                {
                    "type": "webauthn.create",
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "origin": "https://bank.example",
                    "payment": {
                        "browserBoundPublicKey": "%s"
                    }
                }
                """.formatted(base64Url);

        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData result = converter.convert(json.getBytes(StandardCharsets.UTF_8));

        CollectedClientPaymentData paymentData = (CollectedClientPaymentData) result;
        COSEKey actual = paymentData.getPayment().getBrowserBoundPublicKey();
        assertThat(actual).isEqualTo(expectedKey);
    }

    @Test
    void deserialize_should_return_null_when_browserBoundPublicKey_is_absent() {
        String json = """
                {
                    "type": "webauthn.create",
                    "challenge": "dGVzdC1jaGFsbGVuZ2U",
                    "origin": "https://bank.example",
                    "payment": {}
                }
                """;

        CollectedClientDataConverter converter = new CollectedClientDataConverter(objectConverter);
        CollectedClientData result = converter.convert(json.getBytes(StandardCharsets.UTF_8));

        CollectedClientPaymentData paymentData = (CollectedClientPaymentData) result;
        assertThat(paymentData.getPayment().getBrowserBoundPublicKey()).isNull();
    }
}
