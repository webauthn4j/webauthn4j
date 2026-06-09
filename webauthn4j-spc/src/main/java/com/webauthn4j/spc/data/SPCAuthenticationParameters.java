package com.webauthn4j.spc.data;

import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.spc.credential.SPCCredentialRecord;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.spc.data.client.PaymentCredentialInstrument;
import com.webauthn4j.spc.data.client.PaymentCurrencyAmount;
import com.webauthn4j.spc.data.client.PaymentEntityLogo;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Objects;

public class SPCAuthenticationParameters extends AuthenticationParameters {

    private final PaymentCurrencyAmount expectedTotal;
    private final PaymentCredentialInstrument expectedInstrument;
    private final String expectedPayeeName;
    private final Origin expectedPayeeOrigin;
    private final List<PaymentEntityLogo> expectedPaymentEntitiesLogos;

    @SuppressWarnings("java:S107")
    public SPCAuthenticationParameters(
            @NotNull ServerProperty serverProperty,
            @NotNull SPCCredentialRecord credentialRecord,
            @Nullable List<byte[]> allowCredentials,
            boolean userVerificationRequired,
            boolean userPresenceRequired,
            @NotNull PaymentCurrencyAmount expectedTotal,
            @NotNull PaymentCredentialInstrument expectedInstrument,
            @Nullable String expectedPayeeName,
            @Nullable Origin expectedPayeeOrigin,
            @Nullable List<PaymentEntityLogo> expectedPaymentEntitiesLogos) {
        super(serverProperty, credentialRecord, allowCredentials, userVerificationRequired, userPresenceRequired);
        AssertUtil.notNull(expectedTotal, "expectedTotal must not be null");
        AssertUtil.notNull(expectedInstrument, "expectedInstrument must not be null");
        this.expectedTotal = expectedTotal;
        this.expectedInstrument = expectedInstrument;
        this.expectedPayeeName = expectedPayeeName;
        this.expectedPayeeOrigin = expectedPayeeOrigin;
        this.expectedPaymentEntitiesLogos = CollectionUtil.unmodifiableList(expectedPaymentEntitiesLogos);
    }

    @SuppressWarnings("java:S107")
    public SPCAuthenticationParameters(
            @NotNull ServerProperty serverProperty,
            @NotNull SPCCredentialRecord credentialRecord,
            @Nullable List<byte[]> allowCredentials,
            @NotNull PaymentCurrencyAmount expectedTotal,
            @NotNull PaymentCredentialInstrument expectedInstrument,
            @Nullable String expectedPayeeName,
            @Nullable Origin expectedPayeeOrigin,
            @Nullable List<PaymentEntityLogo> expectedPaymentEntitiesLogos) {
        this(serverProperty, credentialRecord, allowCredentials, true, true, expectedTotal, expectedInstrument, expectedPayeeName, expectedPayeeOrigin, expectedPaymentEntitiesLogos);
    }

    public SPCAuthenticationParameters(
            @NotNull ServerProperty serverProperty,
            @NotNull SPCCredentialRecord credentialRecord,
            @NotNull PaymentCurrencyAmount expectedTotal,
            @NotNull PaymentCredentialInstrument expectedInstrument,
            @Nullable String expectedPayeeName,
            @Nullable Origin expectedPayeeOrigin) {
        this(serverProperty, credentialRecord, null, true, true, expectedTotal, expectedInstrument, expectedPayeeName, expectedPayeeOrigin, null);
    }

    @Override
    public @NotNull SPCCredentialRecord getCredentialRecord() {
        return (SPCCredentialRecord) super.getCredentialRecord();
    }

    public @NotNull PaymentCurrencyAmount getExpectedTotal() {
        return expectedTotal;
    }

    public @NotNull PaymentCredentialInstrument getExpectedInstrument() {
        return expectedInstrument;
    }

    public @Nullable String getExpectedPayeeName() {
        return expectedPayeeName;
    }

    public @Nullable Origin getExpectedPayeeOrigin() {
        return expectedPayeeOrigin;
    }

    public @Nullable List<PaymentEntityLogo> getExpectedPaymentEntitiesLogos() {
        return expectedPaymentEntitiesLogos;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        SPCAuthenticationParameters that = (SPCAuthenticationParameters) o;
        return Objects.equals(expectedTotal, that.expectedTotal) &&
                Objects.equals(expectedInstrument, that.expectedInstrument) &&
                Objects.equals(expectedPayeeName, that.expectedPayeeName) &&
                Objects.equals(expectedPayeeOrigin, that.expectedPayeeOrigin) &&
                Objects.equals(expectedPaymentEntitiesLogos, that.expectedPaymentEntitiesLogos);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), expectedTotal, expectedInstrument, expectedPayeeName, expectedPayeeOrigin, expectedPaymentEntitiesLogos);
    }
}
