package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.SingleValueExtensionInputBase;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;

public class CredentialProtectionExtensionAuthenticatorOutput extends SingleValueExtensionInputBase<CredentialProtectionPolicy> implements RegistrationExtensionAuthenticatorOutput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    public CredentialProtectionExtensionAuthenticatorOutput(@NonNull CredentialProtectionPolicy value) {
        super(value);
    }

    @Override
    public @NonNull String getIdentifier() {
        return ID;
    }

    public @NonNull CredentialProtectionPolicy getCredProtect() {
        return getValue();
    }

    @Override
    public @NonNull CredentialProtectionPolicy getValue(@NonNull String key) {
        if (!key.equals(KEY_CRED_PROTECT)) {
            throw new IllegalArgumentException(String.format("%s is the only valid key.", getIdentifier()));
        }
        return getValue();
    }

    @Override
    public void validate() {
        if (getValue() == null) {
            throw new ConstraintViolationException("credProtect must not be null");
        }
    }
}
