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
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

public class AuthenticationData extends CoreAuthenticationData {

    private final byte[] userHandle;
    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions;

    @SuppressWarnings("squid:S107")
    public AuthenticationData(
            @Nullable byte[] credentialId,
            @Nullable byte[] userHandle,
            @Nullable AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @Nullable byte[] authenticatorDataBytes,
            @Nullable CollectedClientData collectedClientData,
            @Nullable byte[] collectedClientDataBytes,
            @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions,
            @Nullable byte[] signature) {
        super(credentialId, authenticatorData, authenticatorDataBytes, collectedClientDataBytes == null ? null : MessageDigestUtil.createSHA256().digest(collectedClientDataBytes), signature);
        this.userHandle = ArrayUtil.clone(userHandle);
        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
    }

    public @Nullable byte[] getUserHandle() {
        return ArrayUtil.clone(userHandle);
    }

    public @Nullable CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public @Nullable byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public @Nullable AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AuthenticationData that = (AuthenticationData) o;
        return Arrays.equals(userHandle, that.userHandle) &&
                Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(clientExtensions, that.clientExtensions);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), collectedClientData, clientExtensions);
        result = 31 * result + Arrays.hashCode(userHandle);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticationData(" +
                "userHandle=" + ArrayUtil.toHexString(userHandle) +
                ", collectedClientData=" + collectedClientData +
                ", clientExtensions=" + clientExtensions +
                ')';
    }
}
