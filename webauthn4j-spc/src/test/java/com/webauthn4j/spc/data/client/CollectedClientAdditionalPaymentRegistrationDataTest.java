package com.webauthn4j.spc.data.client;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.authenticator.Curve;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CollectedClientAdditionalPaymentRegistrationDataTest {

    private static final COSEKey TEST_KEY = TestDataUtil.createEC2COSEPublicKey();

    @Test
    void constructor_should_create_instance() {
        CollectedClientAdditionalPaymentRegistrationData data =
                new CollectedClientAdditionalPaymentRegistrationData(TEST_KEY);
        assertThat(data.getBrowserBoundPublicKey()).isEqualTo(TEST_KEY);
    }

    @Test
    void constructor_should_allow_null() {
        CollectedClientAdditionalPaymentRegistrationData data =
                new CollectedClientAdditionalPaymentRegistrationData(null);
        assertThat(data.getBrowserBoundPublicKey()).isNull();
    }

    @Test
    void equals_should_return_true_for_same_values() {
        COSEKey key = TestDataUtil.createEC2COSEPublicKey();
        CollectedClientAdditionalPaymentRegistrationData a =
                new CollectedClientAdditionalPaymentRegistrationData(key);
        CollectedClientAdditionalPaymentRegistrationData b =
                new CollectedClientAdditionalPaymentRegistrationData(key);
        assertThat(a).isEqualTo(b);
        assertThat(a).hasSameHashCodeAs(b);
    }

    @Test
    void equals_should_return_false_for_different_values() {
        COSEKey key1 = TestDataUtil.createEC2COSEPublicKey();
        COSEKey key2 = new EC2COSEKey(null, COSEAlgorithmIdentifier.ES256, null, Curve.SECP256R1, new byte[32], new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32});
        CollectedClientAdditionalPaymentRegistrationData a =
                new CollectedClientAdditionalPaymentRegistrationData(key1);
        CollectedClientAdditionalPaymentRegistrationData b =
                new CollectedClientAdditionalPaymentRegistrationData(key2);
        assertThat(a).isNotEqualTo(b);
    }
}
