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

package com.webauthn4j.validator.attestation.statement.androidkey;

import com.webauthn4j.response.attestation.statement.AndroidKeyAttestationStatement;
import com.webauthn4j.response.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.response.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.TestUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Answers.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AndroidKeyAttestationStatementValidatorTest {

    private AndroidKeyAttestationStatementValidator target = new AndroidKeyAttestationStatementValidator();

    @Test
    public void validate_test() {
        RegistrationObject registrationObject = TestUtil.createRegistrationObjectWithAndroidKeyAttestation();
        target.validate(registrationObject);
    }

    @Test
    public void validate_with_teeEnforcedOnly_option_test() {
        RegistrationObject registrationObject = TestUtil.createRegistrationObjectWithAndroidKeyAttestation();
        target.setTeeEnforcedOnly(true);
        assertThat(target.isTeeEnforcedOnly()).isTrue();
        target.validate(registrationObject);
    }

    @Test(expected = BadAttestationStatementException.class)
    public void validate_null_x5c_test1(){
        RegistrationObject registrationObject = mock(RegistrationObject.class, RETURNS_DEEP_STUBS);
        when(registrationObject.getAttestationObject().getAttestationStatement()).thenReturn(new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], null));
        target.validate(registrationObject);
    }

    @Test(expected = BadAttestationStatementException.class)
    public void validate_null_x5c_test2(){
        RegistrationObject registrationObject = mock(RegistrationObject.class, RETURNS_DEEP_STUBS);
        when(registrationObject.getAttestationObject().getAttestationStatement()).thenReturn(new AndroidKeyAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], new AttestationCertificatePath()));
        target.validate(registrationObject);
    }


    @Test(expected = IllegalArgumentException.class)
    public void validate_TPMAttestation_test() {
        RegistrationObject registrationObject = TestUtil.createRegistrationObjectWithTPMAttestation();
        target.validate(registrationObject);
    }

}
