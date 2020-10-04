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

package com.webauthn4j.validator;

import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.test.TestDataUtil;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class RegistrationObjectTest {

    private final ObjectConverter objectConverter = new ObjectConverter();

    @Test
    void getter_test() {

        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.CREATE);
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = new AttestationObjectConverter(objectConverter).convertToBytes(attestationObject);
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = TestDataUtil.createAuthenticatorData();
        byte[] authenticatorDataBytes = new AuthenticatorDataConverter(objectConverter).convert(authenticatorData);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        ServerProperty serverProperty = TestDataUtil.createServerProperty();
        Instant timestamp = Instant.now();
        RegistrationObject registrationObject = new RegistrationObject(
                attestationObject,
                attestationObjectBytes,
                clientData,
                clientDataBytes,
                clientExtensions,
                transports,
                serverProperty,
                timestamp
        );

        assertAll(
                () -> assertThat(registrationObject.getCollectedClientData()).isEqualTo(clientData),
                () -> assertThat(registrationObject.getCollectedClientDataBytes()).isEqualTo(clientDataBytes),
                () -> assertThat(registrationObject.getAttestationObject()).isEqualTo(attestationObject),
                () -> assertThat(registrationObject.getAttestationObjectBytes()).isEqualTo(attestationObjectBytes),
                () -> assertThat(registrationObject.getAuthenticatorDataBytes()).isEqualTo(authenticatorDataBytes),
                () -> assertThat(registrationObject.getTransports()).isEqualTo(transports),
                () -> assertThat(registrationObject.getClientExtensions()).isEqualTo(clientExtensions),
                () -> assertThat(registrationObject.getServerProperty()).isEqualTo(serverProperty),
                () -> assertThat(registrationObject.getTimestamp()).isEqualTo(timestamp)
        );
    }

    @Test
    void equals_hashCode_test() {
        CollectedClientData clientData = TestDataUtil.createClientData(ClientDataType.CREATE);
        byte[] clientDataBytes = new CollectedClientDataConverter(objectConverter).convertToBytes(clientData);
        AttestationObject attestationObject = TestDataUtil.createAttestationObjectWithFIDOU2FAttestationStatement();
        byte[] attestationObjectBytes = new AttestationObjectConverter(objectConverter).convertToBytes(attestationObject);
        Set<AuthenticatorTransport> transports = Collections.emptySet();
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs<>();
        ServerProperty serverProperty = TestDataUtil.createServerProperty();
        Instant timestamp = Instant.now();
        RegistrationObject instanceA = new RegistrationObject(
                attestationObject,
                attestationObjectBytes,
                clientData,
                clientDataBytes,
                clientExtensions,
                transports,
                serverProperty,
                timestamp
        );

        RegistrationObject instanceB = new RegistrationObject(
                attestationObject,
                attestationObjectBytes,
                clientData,
                clientDataBytes,
                clientExtensions,
                transports,
                serverProperty,
                timestamp
        );

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }
}
