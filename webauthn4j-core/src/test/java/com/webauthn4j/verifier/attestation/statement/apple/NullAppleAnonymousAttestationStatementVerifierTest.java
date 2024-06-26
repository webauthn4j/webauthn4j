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

package com.webauthn4j.verifier.attestation.statement.apple;

import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.verifier.CoreRegistrationObject;
import com.webauthn4j.verifier.RegistrationObject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class NullAppleAnonymousAttestationStatementVerifierTest {

    private final NullAppleAnonymousAttestationStatementVerifier target = new NullAppleAnonymousAttestationStatementVerifier();

    @Test
    void verify_test() {
        CoreRegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAppleAttestation();
        target.verify(registrationObject);
    }

    @Test
    void verify_non_AppleAnonymousAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.verify(registrationObject)
        );
    }

}