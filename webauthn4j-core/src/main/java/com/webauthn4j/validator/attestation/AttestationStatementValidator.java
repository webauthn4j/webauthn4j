package com.webauthn4j.validator.attestation;

import com.webauthn4j.validator.WebAuthnRegistrationObject;

public interface AttestationStatementValidator {

    void validate(WebAuthnRegistrationObject registrationObject);

    boolean supports(WebAuthnRegistrationObject registrationObject);

}
