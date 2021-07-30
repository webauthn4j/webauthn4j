package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;
import java.util.Objects;

public class PaymentCredentialInstrument implements Serializable {
    private final String displayName;
    private final String icon;

    @JsonCreator
    public PaymentCredentialInstrument(@NonNull @JsonProperty("displayName") String displayName,
                                       @NonNull @JsonProperty("icon") String icon) {
        this.displayName = displayName;
        this.icon = icon;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getIcon() {
        return icon;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PaymentCredentialInstrument that = (PaymentCredentialInstrument) o;
        return displayName.equals(that.displayName) &&
                icon.equals(that.icon);
    }

    @Override
    public int hashCode() {
        return Objects.hash(displayName, icon);
    }
}
