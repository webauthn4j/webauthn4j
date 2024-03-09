/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data;

import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.util.ArrayUtil;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

public class CoreAuthenticationData {

    private final byte[] credentialId;
    private final AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData;
    private final byte[] authenticatorDataBytes;
    private final byte[] clientDataHash;
    private final byte[] signature;

    @SuppressWarnings("squid:S107")
    public CoreAuthenticationData(
            @Nullable byte[] credentialId,
            @Nullable AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @Nullable byte[] authenticatorDataBytes,
            @Nullable byte[] clientDataHash,
            @Nullable byte[] signature) {
        this.credentialId = ArrayUtil.clone(credentialId);
        this.authenticatorData = authenticatorData;
        this.authenticatorDataBytes = ArrayUtil.clone(authenticatorDataBytes);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
        this.signature = ArrayUtil.clone(signature);
    }

    public @Nullable byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public @Nullable AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> getAuthenticatorData() {
        return authenticatorData;
    }

    public @Nullable byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public @Nullable byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    public @Nullable byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreAuthenticationData that = (CoreAuthenticationData) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Objects.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(authenticatorDataBytes, that.authenticatorDataBytes) &&
                Arrays.equals(clientDataHash, that.clientDataHash) &&
                Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(authenticatorData);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "CoreAuthenticationData(" +
                "credentialId=" + ArrayUtil.toHexString(credentialId) +
                ", authenticatorData=" + authenticatorData +
                ", clientDataHash=" + ArrayUtil.toHexString(clientDataHash) +
                ", signature=" + ArrayUtil.toHexString(signature) +
                ')';
    }
}
