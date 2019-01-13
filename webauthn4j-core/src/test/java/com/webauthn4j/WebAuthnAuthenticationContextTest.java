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

package com.webauthn4j;

import com.webauthn4j.response.WebAuthnAuthenticationContext;
import com.webauthn4j.response.client.ClientDataType;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.server.ServerProperty;
import org.junit.Test;

import static com.webauthn4j.test.TestUtil.createAuthenticatorData;
import static com.webauthn4j.test.TestUtil.createClientData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

public class WebAuthnAuthenticationContextTest {

    private Registry registry = new Registry();

    @Test
    public void getter_test() {

        byte[] collectedClientData = new CollectedClientDataConverter(registry).convertToBytes(createClientData(ClientDataType.GET));
        byte[] authenticatorData = new AuthenticatorDataConverter(registry).convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        ServerProperty serverProperty = mock(ServerProperty.class);
        WebAuthnAuthenticationContext target = new WebAuthnAuthenticationContext(
                collectedClientData, authenticatorData, signature, serverProperty, false);
        assertThat(target.getClientDataJSON()).isEqualTo(collectedClientData);
        assertThat(target.getAuthenticatorData()).isEqualTo(authenticatorData);
        assertThat(target.getSignature()).isEqualTo(signature);
        assertThat(target.getServerProperty()).isEqualTo(serverProperty);
        assertThat(target.isUserVerificationRequired()).isFalse();
    }

    @Test
    public void equals_hashCode_test() {
        byte[] collectedClientData = new CollectedClientDataConverter(registry).convertToBytes(createClientData(ClientDataType.GET));
        byte[] authenticatorData = new AuthenticatorDataConverter(registry).convert(createAuthenticatorData());
        byte[] signature = new byte[]{0x01, 0x23};
        ServerProperty serverProperty = mock(ServerProperty.class);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextA = new WebAuthnAuthenticationContext(
                collectedClientData, authenticatorData, signature, serverProperty, true);
        WebAuthnAuthenticationContext webAuthnAuthenticationContextB = new WebAuthnAuthenticationContext(
                collectedClientData, authenticatorData, signature, serverProperty, true);

        assertThat(webAuthnAuthenticationContextA).isEqualTo(webAuthnAuthenticationContextB);
        assertThat(webAuthnAuthenticationContextA).hasSameHashCodeAs(webAuthnAuthenticationContextB);
    }
}
