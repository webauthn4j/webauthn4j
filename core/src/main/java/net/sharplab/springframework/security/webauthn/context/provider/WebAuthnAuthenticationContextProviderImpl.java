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

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;
import net.sharplab.springframework.security.webauthn.util.jackson.WebAuthnModule;
import net.sharplab.springframework.security.webauthn.util.jackson.deserializer.WebAuthnAuthenticatorDataDeserializer;
import org.springframework.security.core.Authentication;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * {@inheritDoc}
 */
@SuppressWarnings("squid:S1609")
public class WebAuthnAuthenticationContextProviderImpl implements WebAuthnAuthenticationContextProvider {


    private ObjectMapper objectMapper;
    private WebAuthnAuthenticatorDataDeserializer deserializer;
    private RelyingPartyProvider relyingPartyProvider;

    public WebAuthnAuthenticationContextProviderImpl(RelyingPartyProvider relyingPartyProvider) {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new WebAuthnModule());
        this.deserializer = new WebAuthnAuthenticatorDataDeserializer();
        this.relyingPartyProvider = relyingPartyProvider;
    }


    @Override
    public WebAuthnAuthenticationContext provide(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 String credentialId,
                                                 String clientData,
                                                 String authenticatorData,
                                                 String signature,
                                                 Authentication currentAuthentication) {

        byte[] rawClientData = Base64Utils.decodeFromUrlSafeString(clientData);
        byte[] rawAuthenticatorData = Base64Utils.decodeFromUrlSafeString(authenticatorData);
        byte[] signatureBytes = Base64Utils.decodeFromUrlSafeString(signature);

        String clientDataJson = deriveClientDataJson(rawClientData);
        CollectedClientData collectedClientDataObject = deriveClientData(clientDataJson);
        WebAuthnAuthenticatorData authenticatorDataObject = deriveAuthenticatorData(rawAuthenticatorData);
        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnAuthenticationContext(
                credentialId,
                rawClientData,
                rawAuthenticatorData,
                clientDataJson,
                collectedClientDataObject,
                authenticatorDataObject,
                signatureBytes,
                relyingParty,
                currentAuthentication);
    }

    public RelyingPartyProvider getRelyingPartyProvider() {
        return relyingPartyProvider;
    }

    public void setRelyingPartyProvider(RelyingPartyProvider relyingPartyProvider) {
        this.relyingPartyProvider = relyingPartyProvider;
    }

    String deriveClientDataJson(byte[] rawClientData) {
        return new String(rawClientData, StandardCharsets.UTF_8); //TODO: UTF-8?
    }

    CollectedClientData deriveClientData(String clientDataJson) {
        try {
            String trimmedClientDataJson = clientDataJson.replace("\0", "").trim();
            return objectMapper.readValue(trimmedClientDataJson, CollectedClientData.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    WebAuthnAuthenticatorData deriveAuthenticatorData(byte[] rawAuthenticatorData) {
        return deserializer.deserialize(rawAuthenticatorData);
    }

}
