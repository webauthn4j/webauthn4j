package com.webauthn4j.validator.attestation.statement.appleappattest;

import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.RegistrationObject;
import org.junit.jupiter.api.Test;

public class AppleAppAttestStatementValidatorTest {

    private final AppleAppAttestStatementValidator target = new AppleAppAttestStatementValidator();

    @Test
    void validate_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        target.validate(registrationObject);
    }
}
