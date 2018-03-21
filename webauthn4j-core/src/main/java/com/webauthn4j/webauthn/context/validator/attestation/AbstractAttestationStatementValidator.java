package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;
import com.webauthn4j.webauthn.exception.NotImplementedException;

public abstract class AbstractAttestationStatementValidator implements AttestationStatementValidator {


    public void validate(WebAuthnRegistrationContext registrationContext){
        if(!supports(registrationContext)){
            throw new NotImplementedException(); //TODO
        }

        validateSignature(registrationContext);
        validateTrustworthiness(registrationContext);
    }

    protected abstract void validateSignature(WebAuthnRegistrationContext registrationContext);

    protected abstract void validateTrustworthiness(WebAuthnRegistrationContext registrationContext);
}
