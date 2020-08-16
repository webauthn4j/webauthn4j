package com.webauthn4j.validator.attestation.statement.appleappattest;

import com.webauthn4j.data.attestation.statement.AppleAppAttestStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;

public class NullAppleAppAttestStatementValidator extends AbstractStatementValidator<AppleAppAttestStatement> {
    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException(String.format("Specified format '%s' is not supported by %s.",
                    registrationObject.getAttestationObject().getFormat(), this.getClass().getName()));
        }

        return AttestationType.NONE;
    }
}
