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

package com.webauthn4j.test.client;

import com.webauthn4j.util.WIP;

@WIP
public class AuthenticatorAssertionResponse extends AuthenticatorResponse {

    private byte[] authenticatorData;
    private byte[] signature;
    private byte[] userHandle;

    public AuthenticatorAssertionResponse(byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, byte[] userHandle, String clientExtensionsJSON) {
        super(clientDataJSON, clientExtensionsJSON);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public AuthenticatorAssertionResponse(byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, byte[] userHandle) {
        super(clientDataJSON);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }
}
