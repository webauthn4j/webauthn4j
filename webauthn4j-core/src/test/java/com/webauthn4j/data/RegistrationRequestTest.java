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

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("ConstantConditions")
class RegistrationRequestTest {

    @Test
    void constructor_test() {
        // Client properties
        byte[] attestationObject = new byte[32];
        byte[] clientDataJSON = new byte[64];
        String clientExtensionJSON = "{}";  /* set clientExtensionJSON */
        Set<String> transports = Collections.singleton("USB");

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        assertThat(registrationRequest.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(registrationRequest.getClientDataJSON()).isEqualTo(clientDataJSON);
        assertThat(registrationRequest.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON);
        assertThat(registrationRequest.getTransports()).isEqualTo(transports);
    }

    @Test
    void constructor_without_transports_test() {
        // Client properties
        byte[] attestationObject = new byte[32];
        byte[] clientDataJSON = new byte[64];
        String clientExtensionJSON = "{}";  /* set clientExtensionJSON */

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON);
        assertThat(registrationRequest.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(registrationRequest.getClientDataJSON()).isEqualTo(clientDataJSON);
        assertThat(registrationRequest.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON);
        assertThat(registrationRequest.getTransports()).isNull();
    }

    @Test
    void equals_hashCode_test() {
        // Client properties
        byte[] attestationObject = null /* set attestationObject */;
        byte[] clientDataJSON = null /* set clientDataJSON */;

        RegistrationRequest instanceA = new RegistrationRequest(attestationObject, clientDataJSON);
        RegistrationRequest instanceB = new RegistrationRequest(attestationObject, clientDataJSON);

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);

    }

}