package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;

public class CredentialProtectionExtensionAuthenticatorInput implements RegistrationExtensionAuthenticatorInput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    public static final Byte USER_VERIFICATION_OPTIONAL = 0x01;
    public static final Byte USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = 0x02;
    public static final Byte USER_VERIFICATION_REQUIRED = 0x02;

    private final Byte credProtect;

    public CredentialProtectionExtensionAuthenticatorInput(Byte credProtect) {
        this.credProtect = credProtect;
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    public Byte getCredProtect(){
        return credProtect;
    }

    @Override
    public Serializable getValue(String key) {
        if (KEY_CRED_PROTECT.equals(key)) {
            return credProtect;
        }
        throw new IllegalArgumentException(String.format("%s is not valid key.", key));
    }

    @Override
    public void validate() {
        AssertUtil.notNull(credProtect, "credProtect must not be null.");
    }
}
