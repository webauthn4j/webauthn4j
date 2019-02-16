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

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;

import java.util.Objects;

/**
 * Envelope class for WebAuthnRegistrationContext validation result
 */
public class WebAuthnRegistrationContextValidationResponse {

    // ~ Instance fields
    // ================================================================================================

    private CollectedClientData collectedClientData;
    private AttestationObject attestationObject;
    private AuthenticationExtensionsClientOutputs<ExtensionClientOutput> registrationExtensionsClientOutputs;

    public WebAuthnRegistrationContextValidationResponse(
            CollectedClientData collectedClientData,
            AttestationObject attestationObject,
            AuthenticationExtensionsClientOutputs<ExtensionClientOutput> registrationExtensionsClientOutputs) {
        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.registrationExtensionsClientOutputs = registrationExtensionsClientOutputs;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public AuthenticationExtensionsClientOutputs<ExtensionClientOutput> getRegistrationExtensionsClientOutputs() {
        return registrationExtensionsClientOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationContextValidationResponse that = (WebAuthnRegistrationContextValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Objects.equals(registrationExtensionsClientOutputs, that.registrationExtensionsClientOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, attestationObject, registrationExtensionsClientOutputs);
    }
}
