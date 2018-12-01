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
import com.webauthn4j.client.CollectedClientData;
import com.webauthn4j.extension.client.ClientExtensionOutput;

import java.util.Map;
import java.util.Objects;

public class WebAuthnRegistrationContextValidationResponse {

    private CollectedClientData collectedClientData;
    private AttestationObject attestationObject;
    private Map<String, ClientExtensionOutput> clientExtensionOutputs;

    public WebAuthnRegistrationContextValidationResponse(CollectedClientData collectedClientData, AttestationObject attestationObject, Map<String, ClientExtensionOutput> clientExtensionOutputs) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.clientExtensionOutputs = clientExtensionOutputs;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public Map<String, ClientExtensionOutput> getClientExtensionOutputs() {
        return clientExtensionOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationContextValidationResponse that = (WebAuthnRegistrationContextValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Objects.equals(clientExtensionOutputs, that.clientExtensionOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, attestationObject, clientExtensionOutputs);
    }
}
