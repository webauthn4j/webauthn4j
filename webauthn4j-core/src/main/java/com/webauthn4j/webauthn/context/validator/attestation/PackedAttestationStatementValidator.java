package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.attestation.statement.PackedAttestationStatement;
import com.webauthn4j.webauthn.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;
import com.webauthn4j.webauthn.exception.NotImplementedException;

public class PackedAttestationStatementValidator extends AbstractAttestationStatementValidator {
    @Override
    protected void validateSignature(WebAuthnRegistrationContext registrationContext) {
        throw new NotImplementedException();
    }

    @Override
    protected void validateTrustworthiness(WebAuthnRegistrationContext registrationContext) {
        throw new NotImplementedException();
    }

    @Override
    public boolean supports(WebAuthnRegistrationContext registrationContext) {
        WebAuthnAttestationStatement attestationStatement = registrationContext.getAttestationObject().getAttestationStatement();
        return PackedAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
