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

package com.webauthn4j.response;

import com.webauthn4j.request.PublicKeyCredentialType;
import com.webauthn4j.response.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.util.Base64UrlUtil;

public class PublicKeyCredential<T extends AuthenticatorResponse> {

    private String id;
    private byte[] rawId;
    private T authenticatorResponse;
    private AuthenticationExtensionsClientOutputs clientExtensionResults;

    public PublicKeyCredential(byte[] credentialId, T authenticatorResponse, AuthenticationExtensionsClientOutputs clientExtensionResults) {
        this.id = Base64UrlUtil.encodeToString(credentialId);
        this.rawId = credentialId;
        this.authenticatorResponse = authenticatorResponse;
        this.clientExtensionResults = clientExtensionResults;
    }

    /**
     * default constructor for jackson deserialization
     */
    public PublicKeyCredential() {
    }

    public String getType() {
        return PublicKeyCredentialType.PUBLIC_KEY.getValue();
    }

    public String getId() {
        return id;
    }

    public byte[] getRawId() {
        return rawId;
    }

    public T getAuthenticatorResponse() {
        return authenticatorResponse;
    }

    public AuthenticationExtensionsClientOutputs getClientExtensionResults() {
        return clientExtensionResults;
    }
}
