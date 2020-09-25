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

package com.webauthn4j.authenticator;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class CoreAuthenticatorImplTest {

    @Test
    void createFromRegistrationData_test(){
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = new byte[32];
        byte[] clientDataHash = new byte[32];
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        CoreRegistrationData registrationData = new CoreRegistrationData(attestationObject, attestationObjectBytes, clientDataHash, transports);
        CoreAuthenticator authenticator = AuthenticatorImpl.createFromCoreRegistrationData(registrationData);
        assertThat(authenticator.getAttestedCredentialData()).isEqualTo(attestationObject.getAuthenticatorData().getAttestedCredentialData());
        assertThat(authenticator.getAttestationStatement()).isEqualTo(attestationObject.getAttestationStatement());
        assertThat(authenticator.getTransports()).isEqualTo(transports);
        assertThat(authenticator.getCounter()).isEqualTo(attestationObject.getAuthenticatorData().getSignCount());
        assertThat(authenticator.getAuthenticatorExtensions()).isEqualTo(attestationObject.getAuthenticatorData().getExtensions());
    }

}