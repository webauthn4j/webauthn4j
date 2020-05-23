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

import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

/**
 * The PublicKeyCredential interface contains the attributes that are returned to the caller
 * when a new credential is created, or a new assertion is requested.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#iface-pkcredential">§5.1. PublicKeyCredential Interface</a>
 */
public class PublicKeyCredential<R extends AuthenticatorResponse, E extends ExtensionClientOutput<?>> implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final String id;
    private final byte[] rawId;
    private final R authenticatorResponse;
    private final AuthenticationExtensionsClientOutputs<E> clientExtensionResults;

    // ~ Constructor
    // ========================================================================================================

    public PublicKeyCredential(byte[] credentialId, R authenticatorResponse, AuthenticationExtensionsClientOutputs<E> clientExtensionResults) {
        this.id = Base64UrlUtil.encodeToString(credentialId);
        this.rawId = credentialId;
        this.authenticatorResponse = authenticatorResponse;
        this.clientExtensionResults = clientExtensionResults;
    }

    public String getType() {
        return PublicKeyCredentialType.PUBLIC_KEY.getValue();
    }

    public String getId() {
        return id;
    }

    public byte[] getRawId() {
        return ArrayUtil.clone(rawId);
    }

    public R getAuthenticatorResponse() {
        return authenticatorResponse;
    }

    public AuthenticationExtensionsClientOutputs<E> getClientExtensionResults() {
        return clientExtensionResults;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredential<?, ?> that = (PublicKeyCredential<?, ?>) o;
        return Objects.equals(id, that.id) &&
                Arrays.equals(rawId, that.rawId) &&
                Objects.equals(authenticatorResponse, that.authenticatorResponse) &&
                Objects.equals(clientExtensionResults, that.clientExtensionResults);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(id, authenticatorResponse, clientExtensionResults);
        result = 31 * result + Arrays.hashCode(rawId);
        return result;
    }
}
