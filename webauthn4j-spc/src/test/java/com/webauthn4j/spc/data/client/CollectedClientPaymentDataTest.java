package com.webauthn4j.spc.data.client;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CollectedClientPaymentDataTest {

    private static final COSEKey TEST_KEY = TestDataUtil.createEC2COSEPublicKey();

    @Test
    void constructor_and_getters() {
        var challenge = new DefaultChallenge();
        var origin = new Origin("https://example.com");
        var payment = new CollectedClientAdditionalPaymentRegistrationData(TEST_KEY);
        var data = new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE, challenge, origin,
                true, new Origin("https://top.example"), null, payment);

        assertThat(data.getType()).isEqualTo(ClientDataType.WEBAUTHN_CREATE);
        assertThat(data.getChallenge()).isEqualTo(challenge);
        assertThat(data.getOrigin()).isEqualTo(origin);
        assertThat(data.getCrossOrigin()).isTrue();
        assertThat(data.getTopOrigin()).isEqualTo(new Origin("https://top.example"));
        assertThat(data.getPayment()).isEqualTo(payment);
    }

    @Test
    void constructor_should_throw_when_payment_is_null() {
        assertThatThrownBy(() -> new CollectedClientPaymentData(
                ClientDataType.WEBAUTHN_CREATE, new DefaultChallenge(),
                new Origin("https://example.com"), null, null, null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equals_and_hashCode() {
        var challenge = new DefaultChallenge();
        var origin = new Origin("https://example.com");
        var payment = new CollectedClientAdditionalPaymentRegistrationData(TEST_KEY);

        var a = new CollectedClientPaymentData(ClientDataType.WEBAUTHN_CREATE, challenge, origin, null, null, null, payment);
        var b = new CollectedClientPaymentData(ClientDataType.WEBAUTHN_CREATE, challenge, origin, null, null, null, payment);
        assertThat(a).isEqualTo(b).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_payment() {
        var challenge = new DefaultChallenge();
        var origin = new Origin("https://example.com");
        COSEKey key1 = TestDataUtil.createEC2COSEPublicKey();
        COSEKey key2 = new EC2COSEKey(null, COSEAlgorithmIdentifier.ES256, null, Curve.SECP256R1, new byte[32], new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
        var a = new CollectedClientPaymentData(ClientDataType.WEBAUTHN_CREATE, challenge, origin, null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(key1));
        var b = new CollectedClientPaymentData(ClientDataType.WEBAUTHN_CREATE, challenge, origin, null, null, null,
                new CollectedClientAdditionalPaymentRegistrationData(key2));
        assertThat(a).isNotEqualTo(b);
    }

}
