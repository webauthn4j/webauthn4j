package com.webauthn4j.data.payment;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public class PaymentAuthenticationParameters extends AuthenticationParameters {
    private final PaymentCredentialInstrument instrument;
    private final PaymentCurrencyAmount total;
    private final Set<Origin> payeeOrigins;

    public PaymentAuthenticationParameters(@NonNull ServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           @NonNull PaymentCredentialInstrument instrument,
                                           @NonNull PaymentCurrencyAmount total,
                                           @NonNull Set<Origin> payeeOrigins,
                                           boolean userVerificationRequired,
                                           boolean userPresenceRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired, userPresenceRequired);
        AssertUtil.notNull(payeeOrigins, "payeeOrigins must not be null");
        AssertUtil.notNull(instrument, "payment instrument must not be null");
        AssertUtil.notNull(total, "payment amount must not be null");
        this.instrument = instrument;
        this.total = total;
        this.payeeOrigins = payeeOrigins;
    }

    public PaymentAuthenticationParameters(@NonNull ServerProperty serverProperty,
                                           @NonNull Authenticator authenticator,
                                           @Nullable List<byte[]> allowCredentials,
                                           @NonNull PaymentCredentialInstrument instrument,
                                           @NonNull PaymentCurrencyAmount total,
                                           @NonNull Set<Origin> payeeOrigins,
                                           boolean userVerificationRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired);
        AssertUtil.notNull(payeeOrigins, "payeeOrigins must not be null");
        AssertUtil.notNull(instrument, "payment instrument must not be null");
        AssertUtil.notNull(total, "payment amount must not be null");
        this.instrument = instrument;
        this.total = total;
        this.payeeOrigins = payeeOrigins;
    }

    public @NonNull PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    public @NonNull PaymentCurrencyAmount getTotal() {
        return total;
    }

    public @NonNull Set<Origin> getPayeeOrigins() {
        return payeeOrigins;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PaymentAuthenticationParameters that = (PaymentAuthenticationParameters) o;
        return instrument.equals(that.instrument) &&
                total.equals(that.total) &&
                payeeOrigins.equals(that.payeeOrigins);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), instrument, total, payeeOrigins);
    }
}
