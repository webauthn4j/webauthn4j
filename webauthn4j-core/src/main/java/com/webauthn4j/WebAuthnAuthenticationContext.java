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

package com.webauthn4j;

import com.webauthn4j.server.ServerProperty;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;


/**
 * WebAuthnAuthenticationContext
 */
public class WebAuthnAuthenticationContext extends AbstractWebAuthnContext {

    //~ Instance fields ================================================================================================

    // user inputs
    private final byte[] credentialId;
    private final byte[] authenticatorData;
    private final byte[] signature;

    @SuppressWarnings("squid:S00107")
    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] clientDataJSON,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         String clientExtensionsJSON,
                                         ServerProperty serverProperty,
                                         boolean userVerificationRequired,
                                         List<String> expectedExtensionIds) {

        super(
                clientDataJSON,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                expectedExtensionIds
        );

        this.credentialId = credentialId;
        this.signature = signature;
        this.authenticatorData = authenticatorData;
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
        return credentialId;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnAuthenticationContext that = (WebAuthnAuthenticationContext) o;
        return Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {

        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
