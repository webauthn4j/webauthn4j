package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;

public class CollectedClientAdditionalPaymentData implements Serializable {
    private final String rp;
    private final String topOrigin;
    private final String payeeOrigin;
    private final PaymentCurrencyAmount total;
    private final PaymentCredentialInstrument instrument;

    @JsonCreator
    public CollectedClientAdditionalPaymentData(@NonNull @JsonProperty("rp") String rp,
                                                @NonNull @JsonProperty("topOrigin") String topOrigin,
                                                @NonNull @JsonProperty("payeeOrigin") String payeeOrigin,
                                                @NonNull @JsonProperty("total") PaymentCurrencyAmount total,
                                                @NonNull @JsonProperty("instrument") PaymentCredentialInstrument instrument) {
        this.rp = rp;
        this.topOrigin = topOrigin;
        this.payeeOrigin = payeeOrigin;
        this.total = total;
        this.instrument = instrument;
    }

    public String getRp() {
        return rp;
    }

    public String getTopOrigin() {
        return topOrigin;
    }

    public String getPayeeOrigin() {
        return payeeOrigin;
    }

    public PaymentCurrencyAmount getTotal() {
        return total;
    }

    public PaymentCredentialInstrument getInstrument() {
        return instrument;
    }
}
