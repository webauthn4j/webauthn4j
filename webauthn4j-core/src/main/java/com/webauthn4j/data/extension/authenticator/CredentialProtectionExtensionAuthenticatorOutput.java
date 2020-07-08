package com.webauthn4j.data.extension.authenticator;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.io.Serializable;

public class CredentialProtectionExtensionAuthenticatorOutput implements RegistrationExtensionAuthenticatorOutput {

    public static final String ID = "credProtect";
    public static final String KEY_CRED_PROTECT = "credProtect";

    private final CredentialProtectionPolicy credProtect;

    public CredentialProtectionExtensionAuthenticatorOutput(CredentialProtectionPolicy credProtect) {
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
        if(!key.equals(KEY_CRED_PROTECT)){
            throw new IllegalArgumentException(String.format("%s is the only valid key.", getIdentifier()));
        }
        return credProtect;
    }

    @Override
    public void validate() {
        if(credProtect == null){
            throw new ConstraintViolationException("credProtect must not be null");
        }
    }
}
