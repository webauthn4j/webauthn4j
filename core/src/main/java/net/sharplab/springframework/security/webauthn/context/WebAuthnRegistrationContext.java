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

package net.sharplab.springframework.security.webauthn.context;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.client.CollectedClientData;

/**
 * WebAuthnRegistrationContext
 */
public class WebAuthnRegistrationContext {

    private CollectedClientData collectedClientData;
    private byte[] clientDataBytes;
    private WebAuthnAttestationObject attestationObject;
    private byte[] attestationObjectBytes;
    private RelyingParty relyingParty;

    public WebAuthnRegistrationContext(CollectedClientData collectedClientData,
                                       byte[] clientDataBytes,
                                       WebAuthnAttestationObject attestationObject,
                                       byte[] attestationObjectBytes,
                                       RelyingParty relyingParty) {

        this.collectedClientData = collectedClientData;
        this.clientDataBytes = clientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.relyingParty = relyingParty;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getClientDataBytes() {
        return clientDataBytes;
    }

    public WebAuthnAttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }
}
