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

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.CollectionUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * WebAuthn authentication context
 */
public class WebAuthnAuthenticationContext extends AbstractWebAuthnContext {

    // ~ Instance fields
    // ================================================================================================

    // user inputs
    private final byte[] credentialId;
    private final byte[] authenticatorData;
    private final byte[] signature;
    private final byte[] userHandle;

    // ~ Constructor
    // ========================================================================================================

    @SuppressWarnings("squid:S00107")
    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         byte[] userHandle,
                                         String clientExtensionsJSON,
                                         ServerProperty serverProperty,
                                         boolean userVerificationRequired,
                                         boolean userPresenceRequired,
                                         List<String> expectedExtensionIds) {

        super(
                clientDataJSON,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                userPresenceRequired,
                expectedExtensionIds
        );

        this.credentialId = credentialId;
        this.signature = signature;
        this.userHandle = userHandle;
        this.authenticatorData = authenticatorData;
    }

    @SuppressWarnings("squid:S00107")
    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         String clientExtensionsJSON,
                                         ServerProperty serverProperty,
                                         boolean userVerificationRequired,
                                         boolean userPresenceRequired,
                                         List<String> expectedExtensionIds) {

        this(
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature,
                null,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                userPresenceRequired,
                expectedExtensionIds
        );
    }

    @SuppressWarnings("squid:S00107")
    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         String clientExtensionsJSON,
                                         ServerProperty serverProperty,
                                         boolean userVerificationRequired,
                                         List<String> expectedExtensionIds) {

        this(
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                true,
                CollectionUtil.unmodifiableList(expectedExtensionIds)
        );
    }

    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         ServerProperty serverProperty,
                                         boolean userVerificationRequired
    ) {
        this(
                credentialId,
                clientDataJSON,
                authenticatorData,
                signature,
                null,
                serverProperty,
                userVerificationRequired,
                Collections.emptyList()
        );
    }

    public byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public byte[] getAuthenticatorData() {
        return ArrayUtil.clone(authenticatorData);
    }

    public byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    public byte[] getUserHandle() {
        return userHandle;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnAuthenticationContext that = (WebAuthnAuthenticationContext) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature) &&
                Arrays.equals(userHandle, that.userHandle);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        result = 31 * result + Arrays.hashCode(userHandle);
        return result;
    }
}
