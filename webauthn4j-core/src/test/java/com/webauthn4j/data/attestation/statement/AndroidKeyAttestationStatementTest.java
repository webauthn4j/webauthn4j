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
import com.webauthn4j.validator.RegistrationObject;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

class AndroidKeyAttestationStatementTest {

    @Test
    void constructor_test() {
        AttestationCertificatePath certificatePath =  new AttestationCertificatePath();
        new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], certificatePath).validate();
        assertAll(
                () -> assertThatThrownBy(()-> new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], null)).isInstanceOf(IllegalArgumentException.class),
                () -> assertThatThrownBy(()-> new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, null, certificatePath)).isInstanceOf(IllegalArgumentException.class),
                () -> assertThatThrownBy(()-> new AndroidKeyAttestationStatement(null, new byte[32], certificatePath)).isInstanceOf(IllegalArgumentException.class)
        );
    }

    @Test
    void equals_hashCode_test() {
        RegistrationObject registrationObjectA = TestDataUtil.createRegistrationObjectWithAndroidKeyAttestation();
        AndroidKeyAttestationStatement instanceA = (AndroidKeyAttestationStatement) registrationObjectA.getAttestationObject().getAttestationStatement();
        RegistrationObject registrationObjectB = TestDataUtil.createRegistrationObjectWithAndroidKeyAttestation();
        AndroidKeyAttestationStatement instanceB = (AndroidKeyAttestationStatement) registrationObjectB.getAttestationObject().getAttestationStatement();

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}