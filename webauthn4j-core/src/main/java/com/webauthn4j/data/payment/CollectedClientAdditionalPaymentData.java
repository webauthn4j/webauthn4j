package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.util.AssertUtil;
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
        AssertUtil.notNull(rp, "rp must not be null");
        AssertUtil.notNull(topOrigin, "topOrigin must not be null");
        AssertUtil.notNull(payeeOrigin, "payeeOrigin must not be null");
        AssertUtil.notNull(total, "total payment amount must not be null");
        AssertUtil.notNull(instrument, "payment instrument must not be null");
        this.rp = rp;
        this.topOrigin = topOrigin;
        this.payeeOrigin = payeeOrigin;
        this.total = total;
        this.instrument = instrument;
    }

    public @NonNull String getRp() {
        return rp;
    }

    public @NonNull Origin getTopOrigin() {
        return topOrigin;
    }

    public @NonNull Origin getPayeeOrigin() {
        return payeeOrigin;
    }

    public @NonNull PaymentCurrencyAmount getTotal() {
        return total;
    }

    public @NonNull PaymentCredentialInstrument getInstrument() {
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
