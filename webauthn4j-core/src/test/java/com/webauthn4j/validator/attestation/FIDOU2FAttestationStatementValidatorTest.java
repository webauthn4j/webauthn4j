package com.webauthn4j.validator.attestation;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FIDOU2FAttestationStatementValidatorTest {

    private FIDOU2FAttestationStatementValidator target = new FIDOU2FAttestationStatementValidator();

    @Test
    public void validate_invalid_attestation_statement_test(){
        RegistrationObject registrationObject = mock(RegistrationObject.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        when(registrationObject.getAttestationObject()).thenReturn(attestationObject);
        when(attestationObject.getAttestationStatement()).thenReturn(new NoneAttestationStatement());
        assertThatThrownBy(() -> target.validate(registrationObject)).isInstanceOf(UnsupportedAttestationFormatException.class);
    }

}
