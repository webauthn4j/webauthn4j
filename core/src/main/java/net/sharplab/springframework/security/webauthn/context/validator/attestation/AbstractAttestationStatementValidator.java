package net.sharplab.springframework.security.webauthn.context.validator.attestation;

import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.exception.NotImplementedException;

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
