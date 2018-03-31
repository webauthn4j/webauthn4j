package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.webauthn.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.webauthn.context.validator.WebAuthnRegistrationObject;
import com.webauthn4j.webauthn.exception.NotImplementedException;

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
