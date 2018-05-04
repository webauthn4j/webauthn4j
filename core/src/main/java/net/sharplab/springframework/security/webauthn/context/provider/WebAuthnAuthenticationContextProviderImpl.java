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
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@inheritDoc}
 */
@SuppressWarnings("squid:S1609")
public class WebAuthnAuthenticationContextProviderImpl implements WebAuthnAuthenticationContextProvider {



    private RelyingPartyProvider relyingPartyProvider;

    public WebAuthnAuthenticationContextProviderImpl(RelyingPartyProvider relyingPartyProvider) {
        this.relyingPartyProvider = relyingPartyProvider;
    }


    @Override
    public WebAuthnAuthenticationContext provide(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 String credentialId,
                                                 String clientData,
                                                 String authenticatorData,
                                                 String signature) {

        byte[] rawId = Base64Utils.decodeFromUrlSafeString(credentialId);
        byte[] rawClientData = Base64Utils.decodeFromUrlSafeString(clientData);
        byte[] rawAuthenticatorData = Base64Utils.decodeFromUrlSafeString(authenticatorData);
        byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnAuthenticationContext(
                rawId,
                rawClientData,
                rawAuthenticatorData,
                signatureBytes,
                relyingParty);
    }

    public RelyingPartyProvider getRelyingPartyProvider() {
        return relyingPartyProvider;
    }

    public void setRelyingPartyProvider(RelyingPartyProvider relyingPartyProvider) {
        this.relyingPartyProvider = relyingPartyProvider;
    }


}
