package com.webauthn4j.data.extension.client;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;


// The credProtect extension is unusual in that it uses two independent top-level JSON keys
// ("credentialProtectionPolicy" and "enforceCredentialProtectionPolicy") to represent a single
// extension at the Client Extension Input level. Most extensions use a single key.
//
// This is a historical artifact of how the extension was specified. The "enforceCredentialProtectionPolicy"
// key is processed only on the client side and is NOT sent to the authenticator — at the CTAP2 level,
// only the "credProtect" key (an integer) exists.
//
// See: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-credProtect-extension
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
    public @NotNull String getIdentifier() {
        return ID;
    }

    public @Nullable CredentialProtectionPolicy getCredentialProtectionPolicy() {
        return credentialProtectionPolicy;
    }

    public @Nullable Boolean getEnforceCredentialProtectionPolicy() {
        return enforceCredentialProtectionPolicy;
    }

    @Override
    public @Nullable Object getValue(@NotNull String key) {
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
