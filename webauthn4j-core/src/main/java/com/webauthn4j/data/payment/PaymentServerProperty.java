package com.webauthn4j.data.payment;

import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.server.ServerProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Set;

public class PaymentServerProperty extends ServerProperty {
    private final PaymentCredentialInstrument instrument;
    private final PaymentCurrencyAmount total;
    private final Set<Origin> payeeOrigins;

    public PaymentServerProperty(@NonNull Set<Origin> origins,
                                 @NonNull String rpId,
                                 @Nullable Challenge challenge,
                                 @Nullable byte[] tokenBindingId,
                                 @NonNull PaymentCredentialInstrument instrument,
                                 @NonNull PaymentCurrencyAmount total,
                                 @NonNull Set<Origin> payeeOrigins) {
        super(origins, rpId, challenge, tokenBindingId);
        this.instrument = instrument;
        this.total = total;
        this.payeeOrigins = payeeOrigins;
    }

    public PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    public PaymentCurrencyAmount getTotal() {
        return total;
    }

    public Set<Origin> getPayeeOrigins() {
        return payeeOrigins;
    }
}
