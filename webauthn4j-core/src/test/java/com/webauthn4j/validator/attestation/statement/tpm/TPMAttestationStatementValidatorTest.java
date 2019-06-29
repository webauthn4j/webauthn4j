/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator.attestation.statement.tpm;


import com.webauthn4j.data.attestation.statement.TPMIAlgHash;
import com.webauthn4j.data.x500.X500Name;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.TPMAttestationOption;
import com.webauthn4j.test.authenticator.webauthn.TPMAuthenticator;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import javax.naming.NamingException;
import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMAttestationStatementValidatorTest {

    private TPMAuthenticator tpmAuthenticator = new TPMAuthenticator();
    private TPMAttestationStatementValidator target = new TPMAttestationStatementValidator();

    @Test
    void validate_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        target.validate(registrationObject);
    }

    @Test
    void validate_non_TPMAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAndroidKeyAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject)
        );
    }

    @Test
    void getAlgJcaName_test() {
        assertAll(
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA1)).isEqualTo("SHA-1"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA256)).isEqualTo("SHA-256"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA384)).isEqualTo("SHA-384"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA512)).isEqualTo("SHA-512"),
                () -> assertThrows(BadAttestationStatementException.class,
                        () -> target.getAlgJcaName(TPMIAlgHash.TPM_ALG_ERROR)
                ),
                () -> assertThrows(BadAttestationStatementException.class,
                        () -> target.getAlgJcaName(TPMIAlgHash.TPM_ALG_NULL)
                )
        );
    }

    @Test
    void parseTpmSAN_test_case1() throws NamingException, IOException {
        X500Name directoryName = new X500Name("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");
        TPMDeviceProperty tpmDeviceProperty = target.parseTPMDeviceProperty(directoryName);
        assertAll(
                () -> assertThat(tpmDeviceProperty.getManufacturer()).isEqualTo("id:494E5443"), // Intel
                () -> assertThat(tpmDeviceProperty.getPartNumber()).isEqualTo("SPT"),
                () -> assertThat(tpmDeviceProperty.getFirmwareVersion()).isEqualTo("id:00020000")
        );
    }

    @Test
    void parseTpmSAN_test_case2() throws NamingException, IOException {
        X500Name directoryName = new X500Name("2.23.133.2.3=#0c0569643a3133+2.23.133.2.2=#0c074e504354367878+2.23.133.2.1=#0c0b69643a3445353434333030");
        TPMDeviceProperty tpmDeviceProperty = target.parseTPMDeviceProperty(directoryName);
        assertAll(
                () -> assertThat(tpmDeviceProperty.getManufacturer()).isEqualTo("id:4E544300"), // Nuvoton Technology
                () -> assertThat(tpmDeviceProperty.getPartNumber()).isEqualTo("NPCT6xx"),
                () -> assertThat(tpmDeviceProperty.getFirmwareVersion()).isEqualTo("id:13")
        );
    }

    @Test
    void validateAikCert_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        target.validateAikCert(certificate);
    }

    @Test
    void validateAikCert_with_non_empty_subjectDN_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setSubjectDN("O=SharpLab., C=US");
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.validateAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void validateAikCert_without_tcgKpAIKCertificate_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setTcgKpAIKCertificateFlagInExtendedKeyUsage(false);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.validateAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void validateAikCert_with_caFlagInBasicConstraints_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setCAFlagInBasicConstraints(true);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.validateAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void validateAikCert_with_version1_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setX509CertificateVersion(1);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.validateAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }
}
