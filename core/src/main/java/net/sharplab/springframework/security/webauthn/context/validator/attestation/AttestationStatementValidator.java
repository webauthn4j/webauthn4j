package net.sharplab.springframework.security.webauthn.context.validator.attestation;

import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;

public interface AttestationStatementValidator {

    void validate(WebAuthnRegistrationContext registrationContext);

    boolean supports(WebAuthnRegistrationContext registrationContext);

}
