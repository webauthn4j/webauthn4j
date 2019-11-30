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

package com.webauthn4j.data;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class WebAuthnRegistrationRequestTest {

    @Test
    void constructor_test(){
        // Client properties
        byte[] attestationObject = new byte[32];
        byte[] clientDataJSON = new byte[64];
        String clientExtensionJSON = "{}";  /* set clientExtensionJSON */;
        Set<String> transports = Collections.singleton("USB");

        WebAuthnRegistrationRequest webAuthnRegistrationRequest = new WebAuthnRegistrationRequest(attestationObject, clientDataJSON, clientExtensionJSON, transports);
        assertThat(webAuthnRegistrationRequest.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(webAuthnRegistrationRequest.getClientDataJSON()).isEqualTo(clientDataJSON);
        assertThat(webAuthnRegistrationRequest.getClientExtensionsJSON()).isEqualTo(clientExtensionJSON);
        assertThat(webAuthnRegistrationRequest.getTransports()).isEqualTo(transports);
    }

    @Test
    void equals_hashCode_test(){
        // Client properties
        byte[] attestationObject = null /* set attestationObject */;
        byte[] clientDataJSON = null /* set clientDataJSON */;

        WebAuthnRegistrationRequest instanceA = new WebAuthnRegistrationRequest(attestationObject, clientDataJSON);
        WebAuthnRegistrationRequest instanceB = new WebAuthnRegistrationRequest(attestationObject, clientDataJSON);

        assertThat(instanceA).isEqualTo(instanceB);
        assertThat(instanceA).hasSameHashCodeAs(instanceB);

    }

}