package net.sharplab.springframework.security.webauthn.context.validator.attestation.signature;

import net.sharplab.springframework.security.webauthn.attestation.statement.NoneAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

public class NoneAttestationStatementSignatureValidator implements AttestationStatementSignatureValidator {
    @Override
    public void validate(WebAuthnRegistrationContext registrationContext) {
        //nop //TODO
    }

    @Override
    public boolean supports(String format) {
        return NoneAttestationStatement.FORMAT.equals(format);
    }
}
