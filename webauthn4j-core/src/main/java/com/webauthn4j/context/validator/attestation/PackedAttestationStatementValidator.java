package com.webauthn4j.context.validator.attestation;

import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.context.validator.WebAuthnRegistrationObject;
import com.webauthn4j.exception.NotImplementedException;

public class PackedAttestationStatementValidator extends AbstractAttestationStatementValidator {
    @Override
    protected void validateSignature(WebAuthnRegistrationObject registrationObject) {
        throw new NotImplementedException();
    }

    @Override
    protected void validateTrustworthiness(WebAuthnRegistrationObject registrationObject) {
        throw new NotImplementedException();
    }

    @Override
    public boolean supports(WebAuthnRegistrationObject registrationObject) {
        WebAuthnAttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return PackedAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
