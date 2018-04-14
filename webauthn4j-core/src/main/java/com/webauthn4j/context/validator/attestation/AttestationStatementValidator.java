package com.webauthn4j.context.validator.attestation;

import com.webauthn4j.context.validator.WebAuthnRegistrationObject;

public interface AttestationStatementValidator {

    void validate(WebAuthnRegistrationObject registrationObject);

    boolean supports(WebAuthnRegistrationObject registrationObject);

}
