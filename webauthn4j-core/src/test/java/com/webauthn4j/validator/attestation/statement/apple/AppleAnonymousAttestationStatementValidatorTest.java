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

package com.webauthn4j.validator.attestation.statement.apple;

import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppleAnonymousAttestationStatementValidatorTest {

    private final AppleAnonymousAttestationStatementValidator target = new AppleAnonymousAttestationStatementValidator();

    @Test
    void validate_test() {
        CoreRegistrationObject coreRegistrationObject = TestDataUtil.createRegistrationObjectWithAppleAttestation();
        target.validate(coreRegistrationObject);
    }

    @Test
    void validateAttestationStatementNotNull_with_null_test(){
        assertThatThrownBy(()->target.validateAttestationStatementNotNull(null)).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void validate_non_AppleAnonymousAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject)
        );
    }


}