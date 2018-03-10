package net.sharplab.springframework.security.webauthn.context.validator.attestation.signature;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

/**
 * Validates {@link WebAuthnAttestationStatement}'s signature
 */
public class WebAuthnAttestationStatementSignatureValidator implements AttestationStatementSignatureValidator{
    @Override
    public void validate(WebAuthnRegistrationContext registrationContext) {
        throw new IllegalStateException(); //TODO not implemented
    }

    @Override
    public boolean supports(String format) {
        return false; //TODO
    }
}
