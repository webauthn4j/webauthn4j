package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.util.AssertUtil;

import java.io.Serializable;

public class CredentialProtectionExtensionAuthenticatorOutput implements RegistrationExtensionAuthenticatorOutput {

    public static final String ID = "credProtect";

    private final Byte credProtect;

    public CredentialProtectionExtensionAuthenticatorOutput(Byte credProtect) {
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
        if(!key.equals(getIdentifier())){
            throw new IllegalArgumentException(String.format("%s is the only valid key.", getIdentifier()));
        }
        return credProtect;
    }

    @Override
    public void validate() {
        AssertUtil.notNull(credProtect, "credProtect must not be null.");
    }
}
