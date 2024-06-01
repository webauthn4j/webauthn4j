package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.SingleValueExtensionInputBase;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class CredentialProtectionExtensionAuthenticatorInput extends SingleValueExtensionInputBase<CredentialProtectionPolicy> implements RegistrationExtensionAuthenticatorInput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    public CredentialProtectionExtensionAuthenticatorInput(@NotNull CredentialProtectionPolicy value) {
        super(value);
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    public @NotNull CredentialProtectionPolicy getCredProtect() {
        return getValue();
    }

    @Override
    public @NotNull CredentialProtectionPolicy getValue(@NotNull String key) {
        if (KEY_CRED_PROTECT.equals(key)) {
            return getValue();
        }
        throw new IllegalArgumentException(String.format("%s is not valid key.", key));
    }

    @SuppressWarnings({"ConstantConditions", "java:S2583"})
    @Override
    public void validate() {
        // value can be null when deserialized by Jackson
        if (getValue() == null) {
            throw new ConstraintViolationException("credProtect must not be null");
        }
    }
}
