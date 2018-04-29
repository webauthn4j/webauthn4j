package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.validator.RegistrationObject;

public class NoneAttestationStatementValidator extends AbstractAttestationStatementValidator {

    @Override
    protected void validateSignature(RegistrationObject registrationObject) {
        // nop
    }

    @Override
    protected void validateTrustworthiness(RegistrationObject registrationObject) {
        // nop
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return NoneAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
