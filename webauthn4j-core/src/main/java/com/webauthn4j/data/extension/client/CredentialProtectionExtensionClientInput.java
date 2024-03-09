package com.webauthn4j.data.extension.client;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;


public class CredentialProtectionExtensionClientInput implements RegistrationExtensionClientInput {

    public static final String ID = "credProtect";
    public static final String KEY_CREDENTIAL_PROTECTION_POLICY = "credentialProtectionPolicy";
    public static final String KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY = "enforceCredentialProtectionPolicy";

    private final CredentialProtectionPolicy credentialProtectionPolicy;
    private final Boolean enforceCredentialProtectionPolicy;

    public CredentialProtectionExtensionClientInput(
            @Nullable CredentialProtectionPolicy credentialProtectionPolicy,
            @Nullable Boolean enforceCredentialProtectionPolicy) {
        this.credentialProtectionPolicy = credentialProtectionPolicy;
        this.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy;
    }

    public CredentialProtectionExtensionClientInput(@Nullable CredentialProtectionPolicy credentialProtectionPolicy) {
        this(credentialProtectionPolicy, null);
    }

    @Override
    public @NonNull String getIdentifier() {
        return ID;
    }

    public @Nullable CredentialProtectionPolicy getCredentialProtectionPolicy() {
        return credentialProtectionPolicy;
    }

    public @Nullable Boolean getEnforceCredentialProtectionPolicy() {
        return enforceCredentialProtectionPolicy;
    }

    @Override
    public @Nullable Object getValue(@NonNull String key) {
        switch (key) {
            case KEY_CREDENTIAL_PROTECTION_POLICY:
                return credentialProtectionPolicy;
            case KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY:
                return enforceCredentialProtectionPolicy;
            default:
                throw new IllegalArgumentException(String.format("%s is not valid key.", key));
        }
    }

    @Override
    public void validate() {
        if (credentialProtectionPolicy == null) {
            throw new ConstraintViolationException("credentialProtectionPolicy must not be null.");
        }
    }

}
