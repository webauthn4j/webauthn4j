package com.webauthn4j.validator.attestation.packed;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;

public class NullPackedAttestationStatementValidator implements AttestationStatementValidator {
    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        return AttestationType.NONE;
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return PackedAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
