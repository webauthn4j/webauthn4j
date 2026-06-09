package com.webauthn4j.spc.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class SecurePaymentConfirmationRequest {

    private final Challenge challenge;
    private final String rpId;
    private final List<byte[]> credentialIds;
    private final PaymentCredentialInstrument instrument;
    private final Long timeout;
    private final String payeeName;
    private final Origin payeeOrigin;
    private final List<PaymentEntityLogo> paymentEntitiesLogos;
    private final AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions;
    private final List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams;
    private final List<String> locale;
    private final Boolean showOptOut;

    @JsonCreator
    public SecurePaymentConfirmationRequest(
            @NotNull @JsonProperty("challenge") Challenge challenge,
            @NotNull @JsonProperty("rpId") String rpId,
            @NotNull @JsonProperty("credentialIds") List<byte[]> credentialIds,
            @NotNull @JsonProperty("instrument") PaymentCredentialInstrument instrument,
            @Nullable @JsonProperty("timeout") Long timeout,
            @Nullable @JsonProperty("payeeName") String payeeName,
            @Nullable @JsonProperty("payeeOrigin") Origin payeeOrigin,
            @Nullable @JsonProperty("paymentEntitiesLogos") List<PaymentEntityLogo> paymentEntitiesLogos,
            @Nullable @JsonProperty("extensions") AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions,
            @Nullable @JsonProperty("browserBoundPubKeyCredParams") List<PublicKeyCredentialParameters> browserBoundPubKeyCredParams,
            @Nullable @JsonProperty("locale") List<String> locale,
            @Nullable @JsonProperty("showOptOut") Boolean showOptOut) {
        AssertUtil.notNull(challenge, "challenge must not be null");
        AssertUtil.notNull(rpId, "rpId must not be null");
        AssertUtil.notNull(credentialIds, "credentialIds must not be null");
        AssertUtil.notNull(instrument, "instrument must not be null");
        this.challenge = challenge;
        this.rpId = rpId;
        this.credentialIds = CollectionUtil.unmodifiableList(credentialIds);
        this.instrument = instrument;
        this.timeout = timeout;
        this.payeeName = payeeName;
        this.payeeOrigin = payeeOrigin;
        this.paymentEntitiesLogos = CollectionUtil.unmodifiableList(paymentEntitiesLogos);
        this.extensions = extensions;
        this.browserBoundPubKeyCredParams = CollectionUtil.unmodifiableList(browserBoundPubKeyCredParams);
        this.locale = CollectionUtil.unmodifiableList(locale);
        this.showOptOut = showOptOut;
    }

    public @NotNull Challenge getChallenge() {
        return challenge;
    }

    public @NotNull String getRpId() {
        return rpId;
    }

    public @NotNull List<byte[]> getCredentialIds() {
        return credentialIds.stream()
                .map(ArrayUtil::clone)
                .toList();
    }

    public @NotNull PaymentCredentialInstrument getInstrument() {
        return instrument;
    }

    public @Nullable Long getTimeout() {
        return timeout;
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

    public @Nullable AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getExtensions() {
        return extensions;
    }

    public @Nullable List<PublicKeyCredentialParameters> getBrowserBoundPubKeyCredParams() {
        return browserBoundPubKeyCredParams;
    }

    public @Nullable List<String> getLocale() {
        return locale;
    }

    public @Nullable Boolean getShowOptOut() {
        return showOptOut;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurePaymentConfirmationRequest that = (SecurePaymentConfirmationRequest) o;
        return Objects.equals(challenge, that.challenge) &&
                Objects.equals(rpId, that.rpId) &&
                credentialIdsEquals(credentialIds, that.credentialIds) &&
                Objects.equals(instrument, that.instrument) &&
                Objects.equals(timeout, that.timeout) &&
                Objects.equals(payeeName, that.payeeName) &&
                Objects.equals(payeeOrigin, that.payeeOrigin) &&
                Objects.equals(paymentEntitiesLogos, that.paymentEntitiesLogos) &&
                Objects.equals(extensions, that.extensions) &&
                Objects.equals(browserBoundPubKeyCredParams, that.browserBoundPubKeyCredParams) &&
                Objects.equals(locale, that.locale) &&
                Objects.equals(showOptOut, that.showOptOut);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(challenge, rpId, instrument, timeout, payeeName, payeeOrigin,
                paymentEntitiesLogos, extensions, browserBoundPubKeyCredParams, locale, showOptOut);
        result = 31 * result + credentialIdsHashCode(credentialIds);
        return result;
    }

    @Override
    public String toString() {
        return "SecurePaymentConfirmationRequest(" +
                "rpId=" + rpId +
                ", challenge=" + challenge +
                ", instrument=" + instrument +
                ", timeout=" + timeout +
                ", payeeName=" + payeeName +
                ", payeeOrigin=" + payeeOrigin +
                ')';
    }

    private static boolean credentialIdsEquals(@NotNull List<byte[]> a, @NotNull List<byte[]> b) {
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) return false;
        }
        return true;
    }

    private static int credentialIdsHashCode(@NotNull List<byte[]> list) {
        int result = 1;
        for (byte[] element : list) {
            result = 31 * result + Arrays.hashCode(element);
        }
        return result;
    }
}
