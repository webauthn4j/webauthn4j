package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;
import java.util.Objects;

public class PaymentCurrencyAmount implements Serializable {
    private final String currency;
    private final String value;

    @JsonCreator
    public PaymentCurrencyAmount(@NonNull @JsonProperty("currency") String currency,
                                 @NonNull @JsonProperty("value") String value) {
        this.currency = currency;
        this.value = value;
    }

    public String getCurrency() {
        return currency;
    }

    public String getValue() {
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
