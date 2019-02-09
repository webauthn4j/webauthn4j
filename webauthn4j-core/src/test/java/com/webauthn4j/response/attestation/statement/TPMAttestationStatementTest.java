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

package com.webauthn4j.response.attestation.statement;

import com.webauthn4j.test.TestUtil;
import com.webauthn4j.validator.RegistrationObject;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TPMAttestationStatementTest {

    @Test
    public void constructor_test(){

        RegistrationObject registrationObjectA = TestUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement source = (TPMAttestationStatement)registrationObjectA.getAttestationObject().getAttestationStatement();

        new TPMAttestationStatement(source.getAlg(), source.getX5c(), source.getSig(), source.getCertInfo(), source.getPubArea());
    }

    @Test
    public void equals_hashCode_test(){

        RegistrationObject registrationObjectA = TestUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceA = (TPMAttestationStatement)registrationObjectA.getAttestationObject().getAttestationStatement();
        RegistrationObject registrationObjectB = TestUtil.createRegistrationObjectWithTPMAttestation();
        TPMAttestationStatement instanceB = (TPMAttestationStatement)registrationObjectB.getAttestationObject().getAttestationStatement();

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

}