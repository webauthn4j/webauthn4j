package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.webauthn.attestation.statement.WebAuthnAttestationStatement;
import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;
import com.webauthn4j.webauthn.context.validator.WebAuthnRegistrationObject;

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
