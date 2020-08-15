package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class AppleAppAttestStatementTest {

    @Test
    void validate_test() {
        new AppleAppAttestStatement(new AttestationCertificatePath(), new byte[32]).validate();
        assertAll(
                () -> {
                    AppleAppAttestStatement appleAppAttestStatement = new AppleAppAttestStatement(null, new byte[32]);
                    assertThrows(ConstraintViolationException.class, appleAppAttestStatement::validate);
                },
                () -> {
                    AppleAppAttestStatement appleAppAttestStatement = new AppleAppAttestStatement(new AttestationCertificatePath(), null);
                    assertThrows(ConstraintViolationException.class, appleAppAttestStatement::validate);
                }
        );
    }

    @Test
    void equals_hashCode_test() {
        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        AppleAppAttestStatement instanceA = (AppleAppAttestStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        RegistrationObject registrationObjectB = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        AppleAppAttestStatement instanceB = (AppleAppAttestStatement) registrationObjectA.getAttestationObject().getAttestationStatement();

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
