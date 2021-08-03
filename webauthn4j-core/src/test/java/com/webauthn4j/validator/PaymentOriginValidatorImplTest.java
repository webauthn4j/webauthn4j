package com.webauthn4j.validator;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.payment.CollectedClientAdditionalPaymentData;
import com.webauthn4j.data.payment.PaymentAuthenticationParameters;
import com.webauthn4j.data.payment.PaymentCredentialInstrument;
import com.webauthn4j.data.payment.PaymentCurrencyAmount;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.BadOriginException;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class PaymentOriginValidatorImplTest {

    private final PaymentOriginValidator target = new PaymentOriginValidatorImpl();

    private final Origin topOrigin = new Origin("https://example.com");
    private final Origin payeeOrigin = new Origin("https://shop.com");


    @Test
    void test_successful_validation() {
        CollectedClientAdditionalPaymentData collectedClientAdditionalPaymentData = new CollectedClientAdditionalPaymentData(
                "example",
                topOrigin,
                payeeOrigin,
                new PaymentCurrencyAmount("EUR", "15"),
                new PaymentCredentialInstrument("Store", "favicon.ico")
        );

        assertThatCode(()->target.validate(collectedClientAdditionalPaymentData, mockPaymentAuthenticationParameters())).doesNotThrowAnyException();
    }

    @Test
    void test_invalid_payee_origin() {
        CollectedClientAdditionalPaymentData collectedClientAdditionalPaymentData = new CollectedClientAdditionalPaymentData(
                "example",
                topOrigin,
                new Origin("https://evilorigin.com"), //invalid payee origin
                new PaymentCurrencyAmount("EUR", "15"),
                new PaymentCredentialInstrument("Store", "favicon.ico")
        );

        assertThrows(BadOriginException.class, () -> target.validate(collectedClientAdditionalPaymentData, mockPaymentAuthenticationParameters()));
    }

    @Test
    void test_invalid_top_origin() {
        CollectedClientAdditionalPaymentData collectedClientAdditionalPaymentData = new CollectedClientAdditionalPaymentData(
                "example",
                new Origin("https://invalidtoporigin.com"), // invalid top origin
                payeeOrigin,
                new PaymentCurrencyAmount("EUR", "15"),
                new PaymentCredentialInstrument("Store", "favicon.ico")
        );

        assertThrows(BadOriginException.class, () -> target.validate(collectedClientAdditionalPaymentData, mockPaymentAuthenticationParameters()));
    }

    private PaymentAuthenticationParameters mockPaymentAuthenticationParameters() {
        ServerProperty serverProperty = new ServerProperty(
                Collections.singleton(topOrigin),
                "example.com",
                TestDataUtil.createChallenge(),
                null
        );

        return new PaymentAuthenticationParameters(
                serverProperty,
                TestDataUtil.createAuthenticator(),
                null,
                new PaymentCredentialInstrument("Store", "favicon.ico"),
                new PaymentCurrencyAmount("EUR", "100"),
                Collections.singleton(payeeOrigin),
                false,
                true

        );
    }

}
