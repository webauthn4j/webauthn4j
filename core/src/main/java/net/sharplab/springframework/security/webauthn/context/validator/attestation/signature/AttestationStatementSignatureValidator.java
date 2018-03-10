package net.sharplab.springframework.security.webauthn.context.validator.attestation.signature;

import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

/**
 * Validates {@link WebAuthnAttestationStatement}'s signature
 */
public interface AttestationStatementSignatureValidator {

    void validate(WebAuthnRegistrationContext registrationContext);

    boolean supports(String format);
}
