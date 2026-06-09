package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class CollectedClientPaymentData extends CollectedClientData {

    @JsonTypeInfo(use = JsonTypeInfo.Id.DEDUCTION, defaultImpl = CollectedClientAdditionalPaymentRegistrationData.class)
    @JsonSubTypes({
            @JsonSubTypes.Type(CollectedClientAdditionalPaymentData.class),
            @JsonSubTypes.Type(CollectedClientAdditionalPaymentRegistrationData.class)
    })
    private final CollectedClientAdditionalPaymentDataUnion payment;

    @JsonCreator
    public CollectedClientPaymentData(
            @NotNull @JsonProperty("type") ClientDataType type,
            @NotNull @JsonProperty("challenge") Challenge challenge,
            @NotNull @JsonProperty("origin") Origin origin,
            @Nullable @JsonProperty("crossOrigin") Boolean crossOrigin,
            @Nullable @JsonProperty("topOrigin") Origin topOrigin,
            @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding,
            @NotNull @JsonProperty("payment") CollectedClientAdditionalPaymentDataUnion payment) {
        super(type, challenge, origin, crossOrigin, topOrigin, tokenBinding);
        AssertUtil.notNull(payment, "payment must not be null");
        this.payment = payment;
    }

    public @NotNull CollectedClientAdditionalPaymentDataUnion getPayment() {
        return payment;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (!super.equals(o)) return false;
        CollectedClientPaymentData that = (CollectedClientPaymentData) o;
        return Objects.equals(payment, that.payment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), payment);
    }

    @Override
    public String toString() {
        return "CollectedClientPaymentData(" +
                "type=" + getType() +
                ", challenge=" + getChallenge() +
                ", origin=" + getOrigin() +
                ", crossOrigin=" + getCrossOrigin() +
                ", topOrigin=" + getTopOrigin() +
                ", payment=" + payment +
                ')';
    }
}
