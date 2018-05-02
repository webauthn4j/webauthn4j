package com.webauthn4j.validator.attestation;

import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;

public abstract class AbstractAttestationStatementValidator implements AttestationStatementValidator {


    public void validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new UnsupportedAttestationFormatException("Specified format is not supported by " + this.getClass().getName());
        }

        validateSignature(registrationObject);
        validateTrustworthiness(registrationObject);
    }

    protected abstract void validateSignature(RegistrationObject registrationObject);

    protected abstract void validateTrustworthiness(RegistrationObject registrationObject);
}
