package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.webauthn.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;

public class NoneAttestationStatementValidator extends AbstractAttestationStatementValidator {

    @Override
    protected void validateSignature(WebAuthnRegistrationContext registrationContext) {
        // nop
    }

    @Override
    protected void validateTrustworthiness(WebAuthnRegistrationContext registrationContext) {
        // nop
    }

    @Override
    public boolean supports(WebAuthnRegistrationContext registrationContext) {
        WebAuthnAttestationStatement attestationStatement = registrationContext.getAttestationObject().getAttestationStatement();
        return NoneAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
