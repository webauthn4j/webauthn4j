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

package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class TPMAttestationStatementTest {

    @Test
    void constructor_test() {

        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement source = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();

        TPMAttestationStatement tpmAttestationStatement = new TPMAttestationStatement(source.getAlg(), source.getX5c(), source.getSig(), source.getCertInfo(), source.getPubArea());

        assertAll(
                () -> assertThat(tpmAttestationStatement.getAlg()).isEqualTo(source.getAlg()),
                () -> assertThat(tpmAttestationStatement.getX5c()).isEqualTo(source.getX5c()),
                () -> assertThat(tpmAttestationStatement.getSig()).isEqualTo(source.getSig()),
                () -> assertThat(tpmAttestationStatement.getCertInfo()).isEqualTo(source.getCertInfo()),
                () -> assertThat(tpmAttestationStatement.getPubArea()).isEqualTo(source.getPubArea())
        );
    }

    @Test
    void validate_test() {

        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement source = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        TPMAttestationStatement tpmAttestationStatement = new TPMAttestationStatement(source.getAlg(), new AttestationCertificatePath(), source.getSig(), source.getCertInfo(), source.getPubArea());
        assertThrows(ConstraintViolationException.class, tpmAttestationStatement::validate);
    }

    @Test
    void equals_hashCode_test() {

        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceA = (TPMAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        RegistrationObject registrationObjectB = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceB = (TPMAttestationStatement) registrationObjectB.getAttestationObject().getAttestationStatement();

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}