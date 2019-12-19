/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j;

import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.server.ServerProperty;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static com.webauthn4j.test.TestDataUtil.createAuthenticatorData;
import static com.webauthn4j.test.TestDataUtil.createClientData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.Mockito.mock;

class WebAuthnAuthenticationContextTest {

    private JsonConverter jsonConverter = new JsonConverter();
    private CborConverter cborConverter = new CborConverter();


    @Test
    void getter_test() {

        byte[] credentialId = new byte[32];
        byte[] collectedClientData = new CollectedClientDataConverter(jsonConverter).convertToBytes(createClientData(ClientDataType.GET));
        byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        byte[] userHandle = new byte[]{0x45,0x67};
        String clientExtensionsJSON = "{}";
        ServerProperty serverProperty = mock(ServerProperty.class);
        List<String> expectedExtensionIds = Collections.emptyList();
        WebAuthnAuthenticationContext target = new WebAuthnAuthenticationContext(
                credentialId,
                collectedClientData,
                authenticatorData,
                signature,
                userHandle,
                clientExtensionsJSON,
                serverProperty,
                false,
                true,
                expectedExtensionIds);
        assertAll(
                () -> assertThat(target.getCredentialId()).isEqualTo(credentialId),
                () -> assertThat(target.getClientDataJSON()).isEqualTo(collectedClientData),
                () -> assertThat(target.getAuthenticatorData()).isEqualTo(authenticatorData),
                () -> assertThat(target.getSignature()).isEqualTo(signature),
                () -> assertThat(target.getUserHandle()).isEqualTo(userHandle),
                () -> assertThat(target.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON),
                () -> assertThat(target.getServerProperty()).isEqualTo(serverProperty),
                () -> assertThat(target.isUserVerificationRequired()).isFalse(),
                () -> assertThat(target.isUserPresenceRequired()).isTrue(),
                () -> assertThat(target.getExpectedExtensionIds()).isEqualTo(expectedExtensionIds)
        );
    }

    @Test
    void equals_hashCode_test() {
        byte[] credentialId = new byte[32];
        byte[] invalidCredentialId = new byte[16];
        byte[] collectedClientData = new CollectedClientDataConverter(jsonConverter).convertToBytes(createClientData(ClientDataType.GET));
        byte[] authenticatorData = new AuthenticatorDataConverter(cborConverter).convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        ServerProperty serverProperty = mock(ServerProperty.class);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextA = new WebAuthnAuthenticationContext(
                credentialId, collectedClientData, authenticatorData, signature, serverProperty, true);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextB = new WebAuthnAuthenticationContext(
                credentialId, collectedClientData, authenticatorData, signature, serverProperty, true);

        WebAuthnAuthenticationContext webAuthnAuthenticationContextC = new WebAuthnAuthenticationContext(
                invalidCredentialId, collectedClientData, authenticatorData, signature, serverProperty, true);

        assertAll(
                () -> assertThat(webAuthnAuthenticationContextA).isEqualTo(webAuthnAuthenticationContextB),
                () -> assertThat(webAuthnAuthenticationContextA).hasSameHashCodeAs(webAuthnAuthenticationContextB),
                () -> assertThat(webAuthnAuthenticationContextA).isNotEqualTo(webAuthnAuthenticationContextC)
        );
    }
}
