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

package net.sharplab.springframework.security.webauthn.context.provider;

import com.webauthn4j.RelyingParty;
import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import net.sharplab.springframework.security.webauthn.challenge.HttpSessionChallengeRepository;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.Base64Utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Test for WebAuthnAuthenticationContextProviderImpl
 */
public class WebAuthnAuthenticationContextProviderImplTest {

    @Ignore
    @Test
    public void provide_test() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "http://localhost:8080");
        MockHttpServletResponse response = new MockHttpServletResponse();
        String credentialId = "StWIWIe1Fg2hAuPemrFVw9JmvK65xn6okTw5bR5p9K4M58NdExovuNezAn2ToqvbEtSUbIHPVvKoXCE7-PjRy5QNhncuYkn9pKvbM00E5I0";
        String clientData = "eyJjaGFsbGVuZ2UiOiJ4V2ozRWRxMlM2YVlyd1FMWHJtR3JBIiwiaGFzaEFsZyI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAGg";
        Challenge savedChallenge = new DefaultChallenge(new byte[]{0x00});
        Origin origin = new Origin("http", "localhost", 8080);
        String rpId = "localhost";
        String signature = "MEUCIQC42cvnjdgqMVYGPXzf8-CaU4RYPEMgxkzgmFFwn1oC4QIgfrLsvf5WPexdVWBsNckVE3RnXTrzAMX75EgMkpjjQ1I";

        Origin expectedOrigin = new Origin("http", "localhost", 8080);

        RelyingPartyProvider relyingPartyProvider = mock(RelyingPartyProvider.class);
        when(relyingPartyProvider.provide(any(), any())).thenReturn(new RelyingParty(origin, rpId, savedChallenge));
        WebAuthnAuthenticationContextProviderImpl webAuthnContextProvider = new WebAuthnAuthenticationContextProviderImpl(relyingPartyProvider);
        WebAuthnAuthenticationContext context = webAuthnContextProvider.provide(request, response, credentialId, clientData, authenticatorData, signature);
        assertThat(context).isNotNull();
        assertThat(context.getCredentialId()).isEqualTo(credentialId);
        assertThat(context.getCollectedClientData()).isEqualTo(Base64Utils.decodeFromUrlSafeString(clientData));
        assertThat(context.getCollectedClientDataJson()).isEqualTo("{\"challenge\":\"xWj3Edq2S6aYrwQLXrmGrA\",\"hashAlg\":\"SHA-256\",\"origin\":\"http://localhost:8080\"}");
        assertThat(context.getAuthenticatorData()).isEqualTo(Base64Utils.decodeFromUrlSafeString(authenticatorData));
        assertThat(context.getSignature()).isEqualTo(Base64Utils.decodeFromUrlSafeString(signature));
        assertThat(context.getRelyingParty().getChallenge().getValue()).isEqualTo(new byte[]{0x00});
        assertThat(context.getRelyingParty().getOrigin()).isEqualTo(expectedOrigin);
        assertThat(context.getRelyingParty().getRpId()).isEqualTo("localhost");
    }

    @Ignore
    @Test
    public void provide_test_with_custom_rpId() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "http://localhost:8080");
        MockHttpServletResponse response = new MockHttpServletResponse();
        String credentialId = "StWIWIe1Fg2hAuPemrFVw9JmvK65xn6okTw5bR5p9K4M58NdExovuNezAn2ToqvbEtSUbIHPVvKoXCE7-PjRy5QNhncuYkn9pKvbM00E5I0";
        String clientData = "eyJjaGFsbGVuZ2UiOiJ4V2ozRWRxMlM2YVlyd1FMWHJtR3JBIiwiaGFzaEFsZyI6IlNIQS0yNTYiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjgwODAifQ";
        String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAGg";
        String signature = "MEUCIQC42cvnjdgqMVYGPXzf8-CaU4RYPEMgxkzgmFFwn1oC4QIgfrLsvf5WPexdVWBsNckVE3RnXTrzAMX75EgMkpjjQ1I";

        RelyingPartyProviderImpl relyingPartyProvider = new RelyingPartyProviderImpl(new HttpSessionChallengeRepository());
        WebAuthnAuthenticationContextProviderImpl webAuthnContextProvider = new WebAuthnAuthenticationContextProviderImpl(relyingPartyProvider);
        assertThat(relyingPartyProvider.getRpId()).isNull();
        relyingPartyProvider.setRpId("example.com");
        WebAuthnAuthenticationContext context = webAuthnContextProvider.provide(request, response, credentialId, clientData, authenticatorData, signature);
        assertThat(context.getRelyingParty().getRpId()).isEqualTo("example.com");
    }

}
