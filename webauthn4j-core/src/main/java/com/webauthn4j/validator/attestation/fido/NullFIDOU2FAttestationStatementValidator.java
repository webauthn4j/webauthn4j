package com.webauthn4j.validator.attestation.fido;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;

public class NullFIDOU2FAttestationStatementValidator implements AttestationStatementValidator {
    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        return AttestationType.NONE;
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return FIDOU2FAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
