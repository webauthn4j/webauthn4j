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

package com.webauthn4j.appattest.data;

import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import org.jetbrains.annotations.Nullable;

public class DCAssertionData extends CoreAuthenticationData {

    /**
     * Constructor
     *
     * @param keyId                  keyId or credentialId
     * @param authenticatorData      authenticatorData
     * @param authenticatorDataBytes authenticatorData in bytes
     * @param clientDataHash         clientDataHash
     * @param signature              signature
     */
    public DCAssertionData(
            @Nullable byte[] keyId,
            @Nullable AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @Nullable byte[] authenticatorDataBytes,
            @Nullable byte[] clientDataHash,
            @Nullable byte[] signature) {
        super(keyId, authenticatorData, authenticatorDataBytes, clientDataHash, signature);
    }

    // keyId is an alias of credentialId
    public @Nullable byte[] getKeyId() {
        return getCredentialId();
    }
}
