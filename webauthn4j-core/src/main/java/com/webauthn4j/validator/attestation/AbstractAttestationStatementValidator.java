package com.webauthn4j.validator.attestation;

import com.webauthn4j.validator.WebAuthnRegistrationObject;
import com.webauthn4j.util.exception.NotImplementedException;

public abstract class AbstractAttestationStatementValidator implements AttestationStatementValidator {


    public void validate(WebAuthnRegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new NotImplementedException(); //TODO
        }

        validateSignature(registrationObject);
        validateTrustworthiness(registrationObject);
    }

    protected abstract void validateSignature(WebAuthnRegistrationObject registrationObject);

    protected abstract void validateTrustworthiness(WebAuthnRegistrationObject registrationObject);
}
