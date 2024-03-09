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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * The PublicKeyCredential interface contains the attributes that are returned to the caller
 * when a new credential is created, or a new assertion is requested.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#iface-pkcredential">§5.1. PublicKeyCredential Interface</a>
 */
public class PublicKeyCredential<R extends AuthenticatorResponse, E extends ExtensionClientOutput> {

    // ~ Instance fields
    // ================================================================================================

    private final String id;
    private final byte[] rawId;
    private final R response;
    private final AuthenticatorAttachment authenticatorAttachment;
    private final AuthenticationExtensionsClientOutputs<E> clientExtensionResults;

    // ~ Constructor
    // ========================================================================================================

    public PublicKeyCredential(
            @Nullable byte[] credentialId,
            @Nullable R response,
            @Nullable AuthenticationExtensionsClientOutputs<E> clientExtensionResults) {
        this(credentialId, response, null, clientExtensionResults);
    }

    public PublicKeyCredential(
            @Nullable byte[] credentialId,
            @Nullable R response,
            @Nullable AuthenticatorAttachment authenticatorAttachment,
            @Nullable AuthenticationExtensionsClientOutputs<E> clientExtensionResults) {
        this.id = Base64UrlUtil.encodeToString(credentialId);
        this.rawId = credentialId;
        this.response = response;
        this.authenticatorAttachment = authenticatorAttachment;
        this.clientExtensionResults = clientExtensionResults;
    }

    public @NonNull String getType() {
        return PublicKeyCredentialType.PUBLIC_KEY.getValue();
    }

    public @Nullable String getId() {
        return id;
    }

    public @Nullable byte[] getRawId() {
        return ArrayUtil.clone(rawId);
    }

    public @Nullable R getResponse() {
        return response;
    }

    public @Nullable AuthenticatorAttachment getAuthenticatorAttachment() { return authenticatorAttachment; }

    /**
     * @deprecated Renamed to getResponse() to compliant with WebAuthn Standard interface
     * @return AuthenticatorResponse
     */
    @JsonIgnore
    @Deprecated
    public @Nullable R getAuthenticatorResponse() {
        return response;
    }

    public @Nullable AuthenticationExtensionsClientOutputs<E> getClientExtensionResults() {
        return clientExtensionResults;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredential<?, ?> that = (PublicKeyCredential<?, ?>) o;
        return Objects.equals(id, that.id) &&
                Arrays.equals(rawId, that.rawId) &&
                Objects.equals(response, that.response) &&
                Objects.equals(authenticatorAttachment, that.authenticatorAttachment) &&
                Objects.equals(clientExtensionResults, that.clientExtensionResults);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(id, response, authenticatorAttachment, clientExtensionResults);
        result = 31 * result + Arrays.hashCode(rawId);
        return result;
    }

    @Override
    public String toString() {
        return "PublicKeyCredential(" +
                "id=" + id +
                ", response=" + response +
                ", authenticatorAttachment=" + authenticatorAttachment +
                ", clientExtensionResults=" + clientExtensionResults +
                ')';
    }
}
