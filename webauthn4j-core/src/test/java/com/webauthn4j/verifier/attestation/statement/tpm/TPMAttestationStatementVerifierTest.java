/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.verifier.attestation.statement.tpm;


import com.webauthn4j.data.attestation.statement.TPMAttestationStatement;
import com.webauthn4j.data.attestation.statement.TPMIAlgHash;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.test.authenticator.webauthn.TPMAttestationOption;
import com.webauthn4j.test.authenticator.webauthn.TPMAuthenticator;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TPMAttestationStatementVerifierTest {

    private final TPMAuthenticator tpmAuthenticator = new TPMAuthenticator();
    private final TPMAttestationStatementVerifier target = new TPMAttestationStatementVerifier();

    @Test
    void verify_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        target.verify(registrationObject);
    }

    @Test
    void verify_non_TPMAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAndroidKeyAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.verify(registrationObject)
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
    void verifyAikCert_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        target.verifyAikCert(certificate);
    }

    @Test
    void verifyAttestationStatementNotNull_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement attestationStatement = (TPMAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement();
        target.verifyAttestationStatementNotNull(attestationStatement);
    }

    @Test
    void verifyAttestationStatementNotNull_with_null_test() {
        assertThatThrownBy(() -> target.verifyAttestationStatementNotNull(null)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyAikCert_with_non_empty_subjectDN_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setSubjectDN("O=SharpLab., C=US");
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.verifyAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyAikCert_without_tcgKpAIKCertificate_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setTcgKpAIKCertificateFlagInExtendedKeyUsage(false);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.verifyAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyAikCert_with_caFlagInBasicConstraints_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setCAFlagInBasicConstraints(true);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.verifyAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void verifyAikCert_with_version1_test() {
        TPMAttestationOption attestationOption = new TPMAttestationOption();
        attestationOption.setX509CertificateVersion(1);
        X509Certificate certificate = tpmAuthenticator.getAttestationCertificate(null, attestationOption);
        assertThatThrownBy(() -> target.verifyAikCert(certificate)).isInstanceOf(BadAttestationStatementException.class);
    }
}
