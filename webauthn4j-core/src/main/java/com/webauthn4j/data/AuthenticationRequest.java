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

import com.webauthn4j.util.ArrayUtil;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

public class AuthenticationRequest {

    private final byte[] credentialId;
    private final byte[] userHandle;
    private final byte[] authenticatorData;
    private final byte[] clientDataJSON;
    private final String clientExtensionsJSON;
    private final byte[] signature;

    public AuthenticationRequest(
            @Nullable byte[] credentialId,
            @Nullable byte[] userHandle,
            @Nullable byte[] authenticatorData,
            @Nullable byte[] clientDataJSON,
            @Nullable String clientExtensionsJSON,
            @Nullable byte[] signature) {
        this.credentialId = ArrayUtil.clone(credentialId);
        this.userHandle = ArrayUtil.clone(userHandle);
        this.authenticatorData = ArrayUtil.clone(authenticatorData);
        this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.signature = ArrayUtil.clone(signature);
    }

    public AuthenticationRequest(
            @Nullable byte[] credentialId,
            @Nullable byte[] authenticatorData,
            @Nullable byte[] clientDataJSON,
            @Nullable String clientExtensionsJSON,
            @Nullable byte[] signature) {
        this(credentialId, null, authenticatorData, clientDataJSON, clientExtensionsJSON, signature);
    }

    public AuthenticationRequest(
            @Nullable byte[] credentialId,
            @Nullable byte[] userHandle,
            @Nullable byte[] authenticatorData,
            @Nullable byte[] clientDataJSON,
            @Nullable byte[] signature) {
        this(credentialId, userHandle, authenticatorData, clientDataJSON, null, signature);
    }

    public AuthenticationRequest(
            @Nullable byte[] credentialId,
            @Nullable byte[] authenticatorData,
            @Nullable byte[] clientDataJSON,
            @Nullable byte[] signature) {
        this(credentialId, null, authenticatorData, clientDataJSON, signature);
    }

    public @Nullable byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public @Nullable byte[] getUserHandle() {
        return ArrayUtil.clone(userHandle);
    }

    public @Nullable byte[] getAuthenticatorData() {
        return ArrayUtil.clone(authenticatorData);
    }

    public @Nullable byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    public @Nullable String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public @Nullable byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationRequest that = (AuthenticationRequest) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(userHandle, that.userHandle) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
                Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(clientExtensionsJSON);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(userHandle);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticationRequest(" +
                "credentialId=" + ArrayUtil.toHexString(credentialId) +
                ", userHandle=" + ArrayUtil.toHexString(userHandle) +
                ", authenticatorData=" + ArrayUtil.toHexString(authenticatorData) +
                ", clientDataJSON=" + ArrayUtil.toHexString(clientDataJSON) +
                ", clientExtensionsJSON=" + clientExtensionsJSON +
                ", signature=" + ArrayUtil.toHexString(signature) +
                ')';
    }
}
