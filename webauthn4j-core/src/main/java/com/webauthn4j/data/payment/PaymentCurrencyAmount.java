package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;
import java.util.Objects;

public class PaymentCurrencyAmount implements Serializable {
    private final String currency;
    private final String value;

    @JsonCreator
    public PaymentCurrencyAmount(@NonNull @JsonProperty("currency") String currency,
                                 @NonNull @JsonProperty("value") String value) {
        AssertUtil.notNull(currency, "payment amount currency must not be null");
        AssertUtil.notNull(value, "payment amount value must not be null");
        this.currency = currency;
        this.value = value;
    }

    public @NonNull String getCurrency() {
        return currency;
    }

    public @NonNull String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PaymentCurrencyAmount that = (PaymentCurrencyAmount) o;
        return currency.equals(that.currency) &&
                value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(currency, value);
    }
}
