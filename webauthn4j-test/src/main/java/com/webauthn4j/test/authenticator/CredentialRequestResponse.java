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

package com.webauthn4j.test.authenticator;

public class CredentialRequestResponse {

    private byte[] credentialId;
    private byte[] collectedClientDataBytes;
    private byte[] authenticatorDataBytes;
    private byte[] signature;
    private byte[] userHandle;

    public CredentialRequestResponse(byte[] credentialId, byte[] collectedClientDataBytes, byte[] authenticatorDataBytes, byte[] signature, byte[] userHandle) {
        this.credentialId = credentialId;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public byte[] getCollectedClientDataBytes() {
        return collectedClientDataBytes;
    }

    public byte[] getAuthenticatorDataBytes() {
        return authenticatorDataBytes;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }
}
