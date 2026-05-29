package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class PaymentCurrencyAmount {

    private final String currency;
    private final String value;

    @JsonCreator
    public PaymentCurrencyAmount(
            @NotNull @JsonProperty("currency") String currency,
            @NotNull @JsonProperty("value") String value) {
        AssertUtil.notNull(currency, "currency must not be null");
        AssertUtil.notNull(value, "value must not be null");
        this.currency = currency;
        this.value = value;
    }

    public @NotNull String getCurrency() {
        return currency;
    }

    public @NotNull String getValue() {
        return value;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PaymentCurrencyAmount that = (PaymentCurrencyAmount) o;
        return Objects.equals(currency, that.currency) && Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(currency, value);
    }

    @Override
    public String toString() {
        return "PaymentCurrencyAmount(" +
                "currency=" + currency +
                ", value=" + value +
                ')';
    }
}
