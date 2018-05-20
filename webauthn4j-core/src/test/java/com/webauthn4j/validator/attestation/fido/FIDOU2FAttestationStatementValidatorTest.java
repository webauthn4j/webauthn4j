package com.webauthn4j.validator.attestation.fido;

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.KeyUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.fido.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.exception.CertificateException;
import com.webauthn4j.validator.exception.UnsupportedAttestationFormatException;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FIDOU2FAttestationStatementValidatorTest {

    private FIDOU2FAttestationStatementValidator target = new FIDOU2FAttestationStatementValidator();

    @Test
    public void validate_invalid_attestation_statement_test() {
        RegistrationObject registrationObject = mock(RegistrationObject.class);
        AttestationObject attestationObject = mock(AttestationObject.class);
        when(registrationObject.getAttestationObject()).thenReturn(attestationObject);
        when(attestationObject.getAttestationStatement()).thenReturn(new NoneAttestationStatement());
        assertThatThrownBy(() -> target.validate(registrationObject)).isInstanceOf(UnsupportedAttestationFormatException.class);
    }

    @Test
    public void validateAttestationStatement_test(){
        FIDOU2FAttestationStatement attestationStatement = mock(FIDOU2FAttestationStatement.class);
        when(attestationStatement.getX5c()).thenReturn(
                new AttestationCertificatePath(Arrays.asList(
                        TestUtil.load3tierTestAuthenticatorAttestationCertificate(),
                        TestUtil.load3tierTestIntermediateCACertificate()
                ))
        );
        assertThatThrownBy(() -> target.validateAttestationStatement(attestationStatement)).isInstanceOf(CertificateException.class);
    }

    @Test(expected = CertificateException.class)
    public void validatePublicKey_with_rsa_key_test(){
        PublicKey publicKey = mock(PublicKey.class);
        when(publicKey.getAlgorithm()).thenReturn("RSA");
        target.validatePublicKey(publicKey);
    }

    @Test(expected = CertificateException.class)
    public void validatePublicKey_with_non_p256_curve_ec_key_test(){
        KeyPair keyPair = KeyUtil.createECKeyPair(ECUtil.P_521_SPEC);
        target.validatePublicKey(keyPair.getPublic());
    }

}
