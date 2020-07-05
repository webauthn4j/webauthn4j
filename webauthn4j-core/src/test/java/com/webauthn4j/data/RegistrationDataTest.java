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

package com.webauthn4j.data;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class RegistrationDataTest {

    @Test
    void equals_hashCode_test() {

        AttestationObject attestationObject = mock(AttestationObject.class);
        byte[] attestationObjectBytes = new byte[32];
        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        byte[] collectedClientDataBytes = new byte[128];
        String clientExtensionJSON = "";
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> authenticationExtensionsClientOutputs = null;
        Set<AuthenticatorTransport> transports = Collections.emptySet();

        RegistrationData instanceA = new RegistrationData(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                collectedClientDataBytes,
                authenticationExtensionsClientOutputs,
                transports
        );
        RegistrationData instanceB = new RegistrationData(
                attestationObject,
                attestationObjectBytes,
                collectedClientData,
                collectedClientDataBytes,
                authenticationExtensionsClientOutputs,
                transports
        );

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);
    }

}