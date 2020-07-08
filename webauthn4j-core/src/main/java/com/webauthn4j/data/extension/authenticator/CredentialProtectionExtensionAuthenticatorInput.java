package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;

public class CredentialProtectionExtensionAuthenticatorInput implements RegistrationExtensionAuthenticatorInput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    private final CredentialProtectionPolicy credProtect;

    public CredentialProtectionExtensionAuthenticatorInput(CredentialProtectionPolicy credProtect) {
        this.credProtect = credProtect;
    }

    @Override
    public String getIdentifier() {
        return ID;
    }

    public CredentialProtectionPolicy getCredProtect(){
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
        if(credProtect == null){
            throw new ConstraintViolationException("credProtect must not be null");
        }
    }
}
