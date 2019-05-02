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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Test for FIDOU2FAttestationStatement
 */
class FIDOU2FAttestationStatementTest {

    @Test
    void getter_setter_test() {
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(Collections.emptyList());
        byte[] signature = new byte[32];
        FIDOU2FAttestationStatement target = new FIDOU2FAttestationStatement(attestationCertificatePath, signature);
        assertAll(
                () -> assertThat(target.getX5c()).isEqualTo(attestationCertificatePath),
                () -> assertThat(target.getSig()).isEqualTo(signature)
        );
    }

    @Test
    void getFormat_test() {
        FIDOU2FAttestationStatement target = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        assertThat(target.getFormat()).isEqualTo("fido-u2f");
    }


    @Test
    void equals_test() {
        FIDOU2FAttestationStatement instanceA = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();

        assertThat(instanceA).isEqualTo(instanceB);
    }

    @Test
    void equals_test_with_not_equal_certificates() {
        FIDOU2FAttestationStatement instanceA = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(
                new AttestationCertificatePath(Collections.singletonList(TestAttestationUtil.loadFirefoxSWTokenAttestationCertificate()))
        );
        FIDOU2FAttestationStatement instanceB = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(
                new AttestationCertificatePath(Collections.singletonList(TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate()))
        );

        assertThat(instanceA).isNotEqualTo(instanceB);
    }

    @Test
    void hashCode_test() {
        FIDOU2FAttestationStatement instanceA = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();

        assertThat(instanceA.hashCode()).isEqualTo(instanceB.hashCode());
    }

    @Test
    void hashCode_test_with_not_equal_certificates() {
        FIDOU2FAttestationStatement instanceA = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        FIDOU2FAttestationStatement instanceB = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(
                new AttestationCertificatePath(Collections.singletonList(TestAttestationUtil.loadFeitianU2FTokenAttestationCertificate()))
        );

        assertThat(instanceA.hashCode()).isNotEqualTo(instanceB.hashCode());
    }

    @Test
    void validate_test() {
        FIDOU2FAttestationStatement instance = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
        instance.validate();
    }


    @Test
    void validate_with_null_x5c_test() {
        FIDOU2FAttestationStatement instance = new FIDOU2FAttestationStatement(null, new byte[0]);
        assertThrows(ConstraintViolationException.class,
                () -> instance.validate()
        );
    }

    @Test
    void validate_with_empty_x5c_test() {
        FIDOU2FAttestationStatement instance = new FIDOU2FAttestationStatement(new AttestationCertificatePath(Collections.emptyList()), new byte[0]);
        assertThrows(ConstraintViolationException.class,
                () -> instance.validate()
        );
    }

    @Test
    void validate_with_two_certificates_x5c_test() {
        FIDOU2FAttestationStatement instance =
                new FIDOU2FAttestationStatement(
                        new AttestationCertificatePath(Arrays.asList(mock(X509Certificate.class), mock(X509Certificate.class))),
                        new byte[0]
                );
        assertThrows(ConstraintViolationException.class,
                () -> instance.validate()
        );
    }

    @Test
    void validate_with_null_signature_test() {
        FIDOU2FAttestationStatement instance =
                new FIDOU2FAttestationStatement(
                        TestAttestationUtil.load2tierTestAttestationCertificatePath(),
                        null
                );
        assertThrows(ConstraintViolationException.class,
                () -> instance.validate()
        );
    }
}
