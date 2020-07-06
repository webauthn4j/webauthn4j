package com.webauthn4j.data.extension.client;

import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;

public class CredentialProtectionExtensionClientInput implements RegistrationExtensionClientInput{

    public static final String ID = "credProtect";
    public static final String KEY_CREDENTIAL_PROTECTION_POLICY = "credentialProtectionPolicy";
    public static final String KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY = "enforceCredentialProtectionPolicy";

    public static final String USER_VERIFICATION_OPTIONAL = "userVerificationOptional";
    public static final String USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = "userVerificationOptionalWithCredentialIDList";
    public static final String USER_VERIFICATION_REQUIRED = "userVerificationRequired";

    private final String credentialProtectionPolicy;
    private final Boolean enforceCredentialProtectionPolicy;

    public CredentialProtectionExtensionClientInput(
            String credentialProtectionPolicy, Boolean enforceCredentialProtectionPolicy) {
        this.credentialProtectionPolicy = credentialProtectionPolicy;
        this.enforceCredentialProtectionPolicy = enforceCredentialProtectionPolicy;
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    public String creCredentialProtectionPolicy(){
        return credentialProtectionPolicy;
    }

    public Boolean getEnforceCredentialProtectionPolicy(){
        return enforceCredentialProtectionPolicy;
    }

    @Override
    public Serializable getValue(String key) {
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
        AssertUtil.notNull(credentialProtectionPolicy, "credentialProtectionPolicy must not be null.");
    }
}
