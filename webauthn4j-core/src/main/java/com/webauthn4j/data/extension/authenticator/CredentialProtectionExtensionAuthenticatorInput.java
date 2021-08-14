package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.SingleValueExtensionInputBase;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;

public class CredentialProtectionExtensionAuthenticatorInput extends SingleValueExtensionInputBase<CredentialProtectionPolicy> implements RegistrationExtensionAuthenticatorInput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    public CredentialProtectionExtensionAuthenticatorInput(@NonNull CredentialProtectionPolicy value) {
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
