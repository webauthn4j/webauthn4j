package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;

public class CredentialProtectionExtensionAuthenticatorOutput implements RegistrationExtensionAuthenticatorOutput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    private final CredentialProtectionPolicy credProtect;

    public CredentialProtectionExtensionAuthenticatorOutput(@Nullable CredentialProtectionPolicy credProtect) {
        this.credProtect = credProtect;
    }

    @Override
    public @NonNull String getIdentifier() {
        return ID;
    }

    public @Nullable CredentialProtectionPolicy getCredProtect() {
        return credProtect;
    }

    @Override
    public @Nullable Serializable getValue(@NonNull String key) {
        if (!key.equals(KEY_CRED_PROTECT)) {
            throw new IllegalArgumentException(String.format("%s is the only valid key.", getIdentifier()));
        }
        return credProtect;
    }

    @Override
    public void validate() {
        if (credProtect == null) {
            throw new ConstraintViolationException("credProtect must not be null");
        }
    }
}
