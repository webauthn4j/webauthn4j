package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

public class CollectedClientPaymentData extends CollectedClientData {
    private final CollectedClientAdditionalPaymentData additionalPaymentData;

    @JsonCreator
    public CollectedClientPaymentData(@NonNull @JsonProperty("type") ClientDataType type,
                                      @NonNull @JsonProperty("challenge") Challenge challenge,
                                      @NonNull @JsonProperty("origin") Origin origin,
                                      @NonNull @JsonProperty("additionalPaymentData") CollectedClientAdditionalPaymentData additionalPaymentData,
                                      @Nullable @JsonProperty("crossOrigin") Boolean crossOrigin,
                                      @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        super(type, challenge, origin, crossOrigin, tokenBinding);
        AssertUtil.notNull(additionalPaymentData, "additionalPaymentData must not be null");
        this.additionalPaymentData = additionalPaymentData;
    }

    public CollectedClientPaymentData(@NonNull @JsonProperty("type") ClientDataType type,
                                      @NonNull @JsonProperty("challenge") Challenge challenge,
                                      @NonNull @JsonProperty("origin") Origin origin,
                                      @NonNull @JsonProperty("additionalPaymentData") CollectedClientAdditionalPaymentData additionalPaymentData,
                                      @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        super(type, challenge, origin, tokenBinding);
        AssertUtil.notNull(additionalPaymentData, "additionalPaymentData must not be null");
        this.additionalPaymentData = additionalPaymentData;
    }

    public @NonNull CollectedClientAdditionalPaymentData getAdditionalPaymentData() {
        return additionalPaymentData;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CollectedClientPaymentData that = (CollectedClientPaymentData) o;
        return additionalPaymentData.equals(that.additionalPaymentData);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), additionalPaymentData);
    }
}
