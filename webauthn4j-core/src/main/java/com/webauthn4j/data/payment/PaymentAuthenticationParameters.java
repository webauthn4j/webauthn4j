package com.webauthn4j.data.payment;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationParameters;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class PaymentAuthenticationParameters extends AuthenticationParameters {
    private final PaymentCredentialInstrument instrument;
    private final PaymentCurrencyAmount total;

    public PaymentAuthenticationParameters(@NonNull PaymentServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           @NonNull PaymentCredentialInstrument instrument,
                                           @NonNull PaymentCurrencyAmount total,
                                           boolean userVerificationRequired,
                                           boolean userPresenceRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired, userPresenceRequired);
        this.instrument = instrument;
        this.total = total;
    }

    public PaymentAuthenticationParameters(@NonNull PaymentServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           @NonNull PaymentCredentialInstrument instrument,
                                           @NonNull PaymentCurrencyAmount total,
                                           boolean userVerificationRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired);
        this.instrument = instrument;
        this.total = total;
    }

    public PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    public PaymentCurrencyAmount getTotal() {
        return total;
    }
}
