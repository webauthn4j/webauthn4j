package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class PaymentEntityLogo {

    private final String url;
    private final String label;

    @JsonCreator
    public PaymentEntityLogo(
            @NotNull @JsonProperty("url") String url,
            @NotNull @JsonProperty("label") String label) {
        AssertUtil.notNull(url, "url must not be null");
        AssertUtil.notNull(label, "label must not be null");
        this.url = url;
        this.label = label;
    }

    public @NotNull String getUrl() {
        return url;
    }

    public @NotNull String getLabel() {
        return label;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        PaymentEntityLogo that = (PaymentEntityLogo) o;
        return Objects.equals(url, that.url) && Objects.equals(label, that.label);
    }

    @Override
    public int hashCode() {
        return Objects.hash(url, label);
    }

    @Override
    public String toString() {
        return "PaymentEntityLogo(" +
                "url=" + url +
                ", label=" + label +
                ')';
    }
}
