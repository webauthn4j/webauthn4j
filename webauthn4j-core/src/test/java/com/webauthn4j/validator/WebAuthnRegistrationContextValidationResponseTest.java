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

package com.webauthn4j.validator;

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;
import com.webauthn4j.test.TestUtil;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class WebAuthnRegistrationContextValidationResponseTest {

    @Test
    void equals_hashCode_test() {
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        AuthenticationExtensionsClientOutputs<ExtensionClientOutput> registrationExtensionsClientOutputs = new AuthenticationExtensionsClientOutputs<>();
        WebAuthnRegistrationContextValidationResponse instanceA =
                new WebAuthnRegistrationContextValidationResponse(clientData, attestationObject, registrationExtensionsClientOutputs);
        WebAuthnRegistrationContextValidationResponse instanceB =
                new WebAuthnRegistrationContextValidationResponse(clientData, attestationObject, registrationExtensionsClientOutputs);
        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceB).hasSameHashCodeAs(instanceB)
        );
    }
}
