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

import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;

import java.util.Map;
import java.util.Objects;

public class WebAuthnAuthenticationContextValidationResponse {

    private CollectedClientData collectedClientData;
    private AuthenticatorData authenticatorData;
    private AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs;

    public WebAuthnAuthenticationContextValidationResponse(
            CollectedClientData collectedClientData,
            AuthenticatorData authenticatorData,
            AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs) {
        this.collectedClientData = collectedClientData;
        this.authenticatorData = authenticatorData;
        this.authenticationExtensionsClientOutputs = authenticationExtensionsClientOutputs;
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public AuthenticatorData getAuthenticatorData() {
        return authenticatorData;
    }

    public AuthenticationExtensionsClientOutputs getAuthenticationExtensionsClientOutputs() {
        return authenticationExtensionsClientOutputs;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationContextValidationResponse that = (WebAuthnAuthenticationContextValidationResponse) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Objects.equals(authenticationExtensionsClientOutputs, that.authenticationExtensionsClientOutputs);
    }

    @Override
    public int hashCode() {

        return Objects.hash(collectedClientData, authenticatorData, authenticationExtensionsClientOutputs);
    }
}
