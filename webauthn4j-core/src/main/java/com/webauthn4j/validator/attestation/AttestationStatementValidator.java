package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.validator.RegistrationObject;

public interface AttestationStatementValidator {

    AttestationType validate(RegistrationObject registrationObject);

    boolean supports(RegistrationObject registrationObject);

}
