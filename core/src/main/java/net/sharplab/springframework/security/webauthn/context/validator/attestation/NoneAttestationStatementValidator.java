package net.sharplab.springframework.security.webauthn.context.validator.attestation;

import net.sharplab.springframework.security.webauthn.attestation.statement.NoneAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

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
