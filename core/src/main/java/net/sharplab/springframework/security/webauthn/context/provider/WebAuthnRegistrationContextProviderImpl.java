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

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;
import net.sharplab.springframework.security.webauthn.context.WebAuthnRegistrationContext;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToCollectedClientDataConverter;
import net.sharplab.springframework.security.webauthn.converter.Base64StringToWebAuthnAttestationObjectConverter;
import org.springframework.util.Base64Utils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@inheritDoc}
 */
public class WebAuthnRegistrationContextProviderImpl implements WebAuthnRegistrationContextProvider {

    private Base64StringToCollectedClientDataConverter base64StringToCollectedClientDataConverter;
    private Base64StringToWebAuthnAttestationObjectConverter base64StringToWebAuthnAttestationObjectConverter;
    private RelyingPartyProvider relyingPartyProvider;

    public WebAuthnRegistrationContextProviderImpl(RelyingPartyProvider relyingPartyProvider) {
        base64StringToCollectedClientDataConverter = new Base64StringToCollectedClientDataConverter();
        base64StringToWebAuthnAttestationObjectConverter = new Base64StringToWebAuthnAttestationObjectConverter();
        this.relyingPartyProvider = relyingPartyProvider;
    }

    public WebAuthnRegistrationContext provide(HttpServletRequest request, HttpServletResponse response,
                                               String clientDataBase64,
                                               String attestationObjectBase64) {

        CollectedClientData collectedClientData = base64StringToCollectedClientDataConverter.convert(clientDataBase64);
        byte[] clientDataBytes = Base64Utils.decodeFromUrlSafeString(clientDataBase64);
        WebAuthnAttestationObject attestationObject = base64StringToWebAuthnAttestationObjectConverter.convert(attestationObjectBase64);
        byte[] attestationObjectBytes = Base64Utils.decodeFromUrlSafeString(attestationObjectBase64);
        RelyingParty relyingParty = relyingPartyProvider.provide(request, response);

        return new WebAuthnRegistrationContext(collectedClientData, clientDataBytes, attestationObject, attestationObjectBytes, relyingParty);
    }

}
