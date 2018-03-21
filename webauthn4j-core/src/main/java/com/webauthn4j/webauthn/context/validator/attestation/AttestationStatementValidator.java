package com.webauthn4j.webauthn.context.validator.attestation;

import com.webauthn4j.webauthn.context.WebAuthnRegistrationContext;

public interface AttestationStatementValidator {

    void validate(WebAuthnRegistrationContext registrationContext);

    boolean supports(WebAuthnRegistrationContext registrationContext);

}
