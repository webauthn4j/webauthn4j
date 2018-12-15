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

import com.webauthn4j.attestation.AttestationObject;
import com.webauthn4j.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.client.ClientDataType;
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class RegistrationObjectTest {

    @Test
    public void test(){
        Registry registry = new Registry();
        CollectedClientData clientData = TestUtil.createClientData(ClientDataType.CREATE);
        byte[] clientDataBytes = new CollectedClientDataConverter(registry).convertToBytes(clientData);
        AttestationObject attestationObject = TestUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = new AttestationObjectConverter(registry).convertToBytes(attestationObject);
        AuthenticatorData authenticatorData = TestUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(registry).convert(authenticatorData);
        ServerProperty serverProperty = TestUtil.createServerProperty();
        RegistrationObject registrationObject = new RegistrationObject(
                clientData,
                clientDataBytes,
                attestationObject,
                attestationObjectBytes,
                authenticatorDataBytes,
                serverProperty
        );

        assertThat(registrationObject.getCollectedClientData()).isEqualTo(clientData);
        assertThat(registrationObject.getCollectedClientDataBytes()).isEqualTo(clientDataBytes);
        assertThat(registrationObject.getAttestationObject()).isEqualTo(attestationObject);
        assertThat(registrationObject.getAttestationObjectBytes()).isEqualTo(attestationObjectBytes);
        assertThat(registrationObject.getAuthenticatorDataBytes()).isEqualTo(authenticatorDataBytes);
        assertThat(registrationObject.getServerProperty()).isEqualTo(serverProperty);
    }
}
