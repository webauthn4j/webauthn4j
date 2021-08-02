package com.webauthn4j.validator;

import com.webauthn4j.data.payment.CollectedClientAdditionalPaymentData;
import com.webauthn4j.data.payment.PaymentAuthenticationParameters;
import org.checkerframework.checker.nullness.qual.NonNull;

public interface PaymentOriginValidator {

    void validate(@NonNull CollectedClientAdditionalPaymentData clientAdditionalPaymentData, @NonNull PaymentAuthenticationParameters paymentAuthenticationParameters);

}
