package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class CollectedClientAdditionalPaymentRegistrationData implements CollectedClientAdditionalPaymentDataUnion {

    private final COSEKey browserBoundPublicKey;

    @JsonCreator
    public CollectedClientAdditionalPaymentRegistrationData(
            @Nullable @JsonProperty("browserBoundPublicKey") COSEKey browserBoundPublicKey) {
        this.browserBoundPublicKey = browserBoundPublicKey;
    }

    @Override
    public @Nullable COSEKey getBrowserBoundPublicKey() {
        return browserBoundPublicKey;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CollectedClientAdditionalPaymentRegistrationData that = (CollectedClientAdditionalPaymentRegistrationData) o;
        return Objects.equals(browserBoundPublicKey, that.browserBoundPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(browserBoundPublicKey);
    }

    @Override
    public String toString() {
        return "CollectedClientAdditionalPaymentRegistrationData(" +
                "browserBoundPublicKey=" + browserBoundPublicKey +
                ')';
    }
}
