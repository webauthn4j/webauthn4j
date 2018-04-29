package com.webauthn4j.validator.attestation;

import com.webauthn4j.validator.RegistrationObject;

public interface AttestationStatementValidator {

    void validate(RegistrationObject registrationObject);

    boolean supports(RegistrationObject registrationObject);

}
