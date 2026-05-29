package com.webauthn4j.spc.data.extension.client;

import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class AuthenticationExtensionsPaymentOutputs
        implements RegistrationExtensionClientOutput, AuthenticationExtensionClientOutput {

    public static final String ID = "payment";
    public static final String KEY_PAYMENT = "payment";

    private final BrowserBoundSignature browserBoundSignature;

    public AuthenticationExtensionsPaymentOutputs(@Nullable BrowserBoundSignature browserBoundSignature) {
        this.browserBoundSignature = browserBoundSignature;
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    @Override
    public @Nullable Object getValue(@NotNull String key) {
        if (KEY_PAYMENT.equals(key)) {
            return browserBoundSignature;
        }
        throw new IllegalArgumentException(String.format("%s is not valid key.", key));
    }

    public @Nullable BrowserBoundSignature getBrowserBoundSignature() {
        return browserBoundSignature;
    }

    @Override
    public void validate() {
        // browserBoundSignature is optional
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsPaymentOutputs that = (AuthenticationExtensionsPaymentOutputs) o;
        return Objects.equals(browserBoundSignature, that.browserBoundSignature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(browserBoundSignature);
    }

    @Override
    public String toString() {
        return "AuthenticationExtensionsPaymentOutputs(" +
                "browserBoundSignature=" + browserBoundSignature +
                ')';
    }
}
