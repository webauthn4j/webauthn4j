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

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;


@SuppressWarnings("ConstantConditions")
class AuthenticationDataTest {

    @Test
    void getter_test() {
        byte[] credentialId = new byte[32];
        byte[] userHandle = new byte[32];
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = null;
        byte[] authenticatorDataBytes = new byte[64];
        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        byte[] collectedClientDataBytes = new byte[128];
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions = null;
        byte[] signature = new byte[32];

        AuthenticationData instance = new AuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                collectedClientDataBytes,
                clientExtensions,
                signature
        );

        assertThat(instance.getCredentialId()).isEqualTo(credentialId);
        assertThat(instance.getUserHandle()).isEqualTo(userHandle);
        assertThat(instance.getAuthenticatorData()).isEqualTo(authenticatorData);
        assertThat(instance.getAuthenticatorDataBytes()).isEqualTo(authenticatorDataBytes);
        assertThat(instance.getCollectedClientData()).isEqualTo(collectedClientData);
        assertThat(instance.getCollectedClientDataBytes()).isEqualTo(collectedClientDataBytes);
        assertThat(instance.getClientExtensions()).isEqualTo(clientExtensions);
        assertThat(instance.getSignature()).isEqualTo(signature);
    }

    @Test
    void equals_hashCode_test() {

        byte[] credentialId = new byte[32];
        byte[] userHandle = new byte[32];
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = null;
        byte[] authenticatorDataBytes = new byte[64];
        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        byte[] collectedClientDataBytes = new byte[128];
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> authenticationExtensionsClientOutputs = null;
        byte[] signature = new byte[32];

        AuthenticationData instanceA = new AuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                collectedClientDataBytes,
                authenticationExtensionsClientOutputs,
                signature
        );
        AuthenticationData instanceB = new AuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                collectedClientDataBytes,
                authenticationExtensionsClientOutputs,
                signature
        );

        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void toString_test() {

        byte[] credentialId = new byte[32];
        byte[] userHandle = new byte[32];
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = null;
        byte[] authenticatorDataBytes = new byte[64];
        CollectedClientData collectedClientData = mock(CollectedClientData.class);
        byte[] collectedClientDataBytes = new byte[128];
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> authenticationExtensionsClientOutputs = null;
        byte[] signature = new byte[32];

        AuthenticationData instance = new AuthenticationData(
                credentialId,
                userHandle,
                authenticatorData,
                authenticatorDataBytes,
                collectedClientData,
                collectedClientDataBytes,
                authenticationExtensionsClientOutputs,
                signature
        );
        //noinspection ResultOfMethodCallIgnored
        assertThatCode(instance::toString).doesNotThrowAnyException();
    }

}