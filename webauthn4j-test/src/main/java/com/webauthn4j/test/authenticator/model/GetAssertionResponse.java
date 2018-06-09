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

package com.webauthn4j.test.authenticator.model;

public class GetAssertionResponse {

    private byte[] credentialId;
    private byte[] authenticatorData;
    private byte[] signature;
    private byte[] userHandle;

    public byte[] getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public void setAuthenticatorData(byte[] authenticatorData) {
        this.authenticatorData = authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(byte[] userHandle) {
        this.userHandle = userHandle;
    }
}
