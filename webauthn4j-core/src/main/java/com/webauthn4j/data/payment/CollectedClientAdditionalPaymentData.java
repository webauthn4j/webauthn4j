package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.Origin;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;
import java.util.Objects;

public class CollectedClientAdditionalPaymentData implements Serializable {
    private final String rp;
    private final Origin topOrigin;
    private final Origin payeeOrigin;
    private final PaymentCurrencyAmount total;
    private final PaymentCredentialInstrument instrument;

    @JsonCreator
    public CollectedClientAdditionalPaymentData(@NonNull @JsonProperty("rp") String rp,
                                                @NonNull @JsonProperty("topOrigin") Origin topOrigin,
                                                @NonNull @JsonProperty("payeeOrigin") Origin payeeOrigin,
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

    public Origin getTopOrigin() {
        return topOrigin;
    }

    public Origin getPayeeOrigin() {
        return payeeOrigin;
    }

    public PaymentCurrencyAmount getTotal() {
        return total;
    }

    public PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CollectedClientAdditionalPaymentData that = (CollectedClientAdditionalPaymentData) o;
        return rp.equals(that.rp) &&
                topOrigin.equals(that.topOrigin) &&
                payeeOrigin.equals(that.payeeOrigin) &&
                total.equals(that.total) &&
                instrument.equals(that.instrument);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rp, topOrigin, payeeOrigin, total, instrument);
    }
}
