package com.webauthn4j.data.payment;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.challenge.Challenge;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

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
        this.additionalPaymentData = additionalPaymentData;
    }

    public CollectedClientPaymentData(@NonNull @JsonProperty("type") ClientDataType type,
                                      @NonNull @JsonProperty("challenge") Challenge challenge,
                                      @NonNull @JsonProperty("origin") Origin origin,
                                      @NonNull @JsonProperty("additionalPaymentData") CollectedClientAdditionalPaymentData additionalPaymentData,
                                      @Nullable @JsonProperty("tokenBinding") TokenBinding tokenBinding) {
        super(type, challenge, origin, tokenBinding);
        this.additionalPaymentData = additionalPaymentData;
    }

    public @NonNull CollectedClientAdditionalPaymentData getAdditionalPaymentData() {
        return additionalPaymentData;
    }

}
