package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.validator.WebAuthnRegistrationObject;

public class NoneAttestationStatementValidator extends AbstractAttestationStatementValidator {

    @Override
    protected void validateSignature(WebAuthnRegistrationObject registrationObject) {
        // nop
    }

    @Override
    protected void validateTrustworthiness(WebAuthnRegistrationObject registrationObject) {
        // nop
    }

    @Override
    public boolean supports(WebAuthnRegistrationObject registrationObject) {
        WebAuthnAttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return NoneAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
