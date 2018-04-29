package com.webauthn4j.validator.attestation;

import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.util.exception.NotImplementedException;

public abstract class AbstractAttestationStatementValidator implements AttestationStatementValidator {


    public void validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new NotImplementedException(); //TODO
        }

        validateSignature(registrationObject);
        validateTrustworthiness(registrationObject);
    }

    protected abstract void validateSignature(RegistrationObject registrationObject);

    protected abstract void validateTrustworthiness(RegistrationObject registrationObject);
}
