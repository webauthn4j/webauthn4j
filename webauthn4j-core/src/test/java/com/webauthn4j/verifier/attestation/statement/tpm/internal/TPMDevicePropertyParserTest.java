package com.webauthn4j.verifier.attestation.statement.tpm.internal;

import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.TPMAttestationStatement;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.attestation.statement.tpm.TPMDeviceProperty;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TPMDevicePropertyParserTest {

    @Test
    void parse_test() {
        CoreRegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement attestationStatement = (TPMAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        AttestationCertificatePath certPath = attestationStatement.getX5c();
        X509Certificate certificate = certPath.getEndEntityAttestationCertificate().getCertificate();

        TPMDeviceProperty result = TPMDevicePropertyParser.parse(certificate);

        assertAll(
                () -> assertThat(result.getManufacturer()).isEqualTo("id:4E544300"),
                () -> assertThat(result.getPartNumber()).isEqualTo("NPCT6xx"),
                () -> assertThat(result.getFirmwareVersion()).isEqualTo("id:13")
        );
    }

    @Test
    void parse_throws_when_san_extension_missing_test() {
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getExtensionValue("2.5.29.17")).thenReturn(null);

        assertThatThrownBy(() -> TPMDevicePropertyParser.parse(certificate))
                .isInstanceOf(BadAttestationStatementException.class);
    }
}
