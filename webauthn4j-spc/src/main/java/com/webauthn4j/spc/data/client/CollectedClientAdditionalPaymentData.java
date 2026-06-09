package com.webauthn4j.spc.data.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Objects;

public class CollectedClientAdditionalPaymentData implements CollectedClientAdditionalPaymentDataUnion {

    private final String rpId;
    private final Origin topOrigin;
    private final String payeeName;
    private final Origin payeeOrigin;
    private final List<PaymentEntityLogo> paymentEntitiesLogos;
    private final PaymentCurrencyAmount total;
    private final PaymentCredentialInstrument instrument;
    private final COSEKey browserBoundPublicKey;

    @JsonCreator
    public CollectedClientAdditionalPaymentData(
            @NotNull @JsonProperty("rpId") String rpId,
            @NotNull @JsonProperty("topOrigin") Origin topOrigin,
            @Nullable @JsonProperty("payeeName") String payeeName,
            @Nullable @JsonProperty("payeeOrigin") Origin payeeOrigin,
            @Nullable @JsonProperty("paymentEntitiesLogos") List<PaymentEntityLogo> paymentEntitiesLogos,
            @NotNull @JsonProperty("total") PaymentCurrencyAmount total,
            @NotNull @JsonProperty("instrument") PaymentCredentialInstrument instrument,
            @Nullable @JsonProperty("browserBoundPublicKey") COSEKey browserBoundPublicKey) {
        AssertUtil.notNull(rpId, "rpId must not be null");
        AssertUtil.notNull(topOrigin, "topOrigin must not be null");
        AssertUtil.notNull(total, "total must not be null");
        AssertUtil.notNull(instrument, "instrument must not be null");
        this.rpId = rpId;
        this.topOrigin = topOrigin;
        this.payeeName = payeeName;
        this.payeeOrigin = payeeOrigin;
        this.paymentEntitiesLogos = CollectionUtil.unmodifiableList(paymentEntitiesLogos);
        this.total = total;
        this.instrument = instrument;
        this.browserBoundPublicKey = browserBoundPublicKey;
    }

    public @NotNull String getRpId() {
        return rpId;
    }

    public @NotNull Origin getTopOrigin() {
        return topOrigin;
    }

    public @Nullable String getPayeeName() {
        return payeeName;
    }

    public @Nullable Origin getPayeeOrigin() {
        return payeeOrigin;
    }

    public @Nullable List<PaymentEntityLogo> getPaymentEntitiesLogos() {
        return paymentEntitiesLogos;
    }

    public @NotNull PaymentCurrencyAmount getTotal() {
        return total;
    }

    public @NotNull PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    @Override
    public @Nullable COSEKey getBrowserBoundPublicKey() {
        return browserBoundPublicKey;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        CollectedClientAdditionalPaymentData that = (CollectedClientAdditionalPaymentData) o;
        return Objects.equals(rpId, that.rpId) &&
                Objects.equals(topOrigin, that.topOrigin) &&
                Objects.equals(payeeName, that.payeeName) &&
                Objects.equals(payeeOrigin, that.payeeOrigin) &&
                Objects.equals(paymentEntitiesLogos, that.paymentEntitiesLogos) &&
                Objects.equals(total, that.total) &&
                Objects.equals(instrument, that.instrument) &&
                Objects.equals(browserBoundPublicKey, that.browserBoundPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rpId, topOrigin, payeeName, payeeOrigin, paymentEntitiesLogos, total, instrument, browserBoundPublicKey);
    }

    @Override
    public String toString() {
        return "CollectedClientAdditionalPaymentData(" +
                "rpId=" + rpId +
                ", topOrigin=" + topOrigin +
                ", payeeName=" + payeeName +
                ", payeeOrigin=" + payeeOrigin +
                ", paymentEntitiesLogos=" + paymentEntitiesLogos +
                ", total=" + total +
                ", instrument=" + instrument +
                ", browserBoundPublicKey=" + browserBoundPublicKey +
                ')';
    }
}
