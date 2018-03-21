package net.sharplab.springframework.security.webauthn.context.validator.attestation;

import net.sharplab.springframework.security.webauthn.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.exception.NotImplementedException;

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
