package com.webauthn4j.spc.data.extension.client;

import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.util.CollectionUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Objects;

public class AuthenticationExtensionsPaymentInputs
        implements RegistrationExtensionClientInput, AuthenticationExtensionClientInput {

    public static final String ID = "payment";
    public static final String KEY_PAYMENT = "payment";

    private final Boolean isPayment;
    private final List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams;
    private final String rpId;
    private final Origin topOrigin;
    private final String payeeName;
    private final Origin payeeOrigin;
    private final List<PaymentEntityLogo> paymentEntitiesLogos;
    private final PaymentCurrencyAmount total;
    private final PaymentCredentialInstrument instrument;

    /**
     * Constructor for registration. Sets isPayment to true.
     */
    public AuthenticationExtensionsPaymentInputs(
            @Nullable List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams) {
        this(true, browserBoundPubKeyCredParams, null, null, null, null, null, null, null);
    }

    /**
     * Constructor for authentication.
     */
    @SuppressWarnings("java:S107")
    public AuthenticationExtensionsPaymentInputs(
            @Nullable String rpId,
            @Nullable Origin topOrigin,
            @Nullable String payeeName,
            @Nullable Origin payeeOrigin,
            @Nullable List<PaymentEntityLogo> paymentEntitiesLogos,
            @Nullable PaymentCurrencyAmount total,
            @Nullable PaymentCredentialInstrument instrument,
            @Nullable List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams) {
        this(true, browserBoundPubKeyCredParams, rpId, topOrigin, payeeName, payeeOrigin, paymentEntitiesLogos, total, instrument);
    }

    /**
     * Constructor for JSON deserialization. Accepts all fields.
     */
    @SuppressWarnings("java:S107")
    public AuthenticationExtensionsPaymentInputs(
            @Nullable Boolean isPayment,
            @Nullable List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams,
            @Nullable String rpId,
            @Nullable Origin topOrigin,
            @Nullable String payeeName,
            @Nullable Origin payeeOrigin,
            @Nullable List<PaymentEntityLogo> paymentEntitiesLogos,
            @Nullable PaymentCurrencyAmount total,
            @Nullable PaymentCredentialInstrument instrument) {
        this.isPayment = isPayment;
        this.browserBoundPubKeyCredParams = CollectionUtil.unmodifiableList(browserBoundPubKeyCredParams);
        this.rpId = rpId;
        this.topOrigin = topOrigin;
        this.payeeName = payeeName;
        this.payeeOrigin = payeeOrigin;
        this.paymentEntitiesLogos = CollectionUtil.unmodifiableList(paymentEntitiesLogos);
        this.total = total;
        this.instrument = instrument;
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    @Override
    public @Nullable Object getValue(@NotNull String key) {
        if (KEY_PAYMENT.equals(key)) {
            return this;
        }
        throw new IllegalArgumentException(String.format("%s is not valid key.", key));
    }

    public @Nullable Boolean getIsPayment() {
        return isPayment;
    }

    public @Nullable List<PublicKeyCredentialParameters> getBrowserBoundPubKeyCredParams() {
        return browserBoundPubKeyCredParams;
    }

    public @Nullable String getRpId() {
        return rpId;
    }

    public @Nullable Origin getTopOrigin() {
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

    public @Nullable PaymentCurrencyAmount getTotal() {
        return total;
    }

    public @Nullable PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    @Override
    public void validate() {
        // validation is context-dependent
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsPaymentInputs that = (AuthenticationExtensionsPaymentInputs) o;
        return Objects.equals(isPayment, that.isPayment) &&
                Objects.equals(browserBoundPubKeyCredParams, that.browserBoundPubKeyCredParams) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(topOrigin, that.topOrigin) &&
                Objects.equals(payeeName, that.payeeName) &&
                Objects.equals(payeeOrigin, that.payeeOrigin) &&
                Objects.equals(paymentEntitiesLogos, that.paymentEntitiesLogos) &&
                Objects.equals(total, that.total) &&
                Objects.equals(instrument, that.instrument);
    }

    @Override
    public int hashCode() {
        return Objects.hash(isPayment, browserBoundPubKeyCredParams, rpId, topOrigin, payeeName, payeeOrigin, paymentEntitiesLogos, total, instrument);
    }

    @Override
    public String toString() {
        return "AuthenticationExtensionsPaymentInputs(" +
                "isPayment=" + isPayment +
                ", browserBoundPubKeyCredParams=" + browserBoundPubKeyCredParams +
                ", rpId=" + rpId +
                ", topOrigin=" + topOrigin +
                ", payeeName=" + payeeName +
                ", payeeOrigin=" + payeeOrigin +
                ", paymentEntitiesLogos=" + paymentEntitiesLogos +
                ", total=" + total +
                ", instrument=" + instrument +
                ')';
    }
}
