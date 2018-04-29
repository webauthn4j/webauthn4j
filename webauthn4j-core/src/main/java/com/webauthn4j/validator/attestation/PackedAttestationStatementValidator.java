package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.util.exception.NotImplementedException;

public class PackedAttestationStatementValidator extends AbstractAttestationStatementValidator {
    @Override
    protected void validateSignature(RegistrationObject registrationObject) {
        throw new NotImplementedException();
    }

    @Override
    protected void validateTrustworthiness(RegistrationObject registrationObject) {
        throw new NotImplementedException();
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return PackedAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
