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

package com.webauthn4j.data;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.util.ArrayUtil;

import java.util.Arrays;
import java.util.Objects;

public class WebAuthnAuthenticationData {

    private final byte[] credentialId;
    private final byte[] userHandle;
    private final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions;
    private final byte[] signature;

    public WebAuthnAuthenticationData(
            byte[] credentialId,
            byte[] userHandle,
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            byte[] authenticatorDataBytes,
            CollectedClientData collectedClientData,
            byte[] collectedClientDataBytes,
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            byte[] signature) {
        this.credentialId = ArrayUtil.clone(credentialId);
        this.userHandle = ArrayUtil.clone(userHandle);
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = ArrayUtil.clone(authenticatorDataBytes);
        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
        this.signature = ArrayUtil.clone(signature);
    }

    public byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public byte[] getUserHandle() {
        return ArrayUtil.clone(userHandle);
    }

    public AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    public byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationData that = (WebAuthnAuthenticationData) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(userHandle, that.userHandle) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(authenticatorDataBytes, that.authenticatorDataBytes) &&
                Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(clientExtensions, that.clientExtensions) &&
                Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(authenticatorData, collectedClientData, clientExtensions);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(userHandle);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
