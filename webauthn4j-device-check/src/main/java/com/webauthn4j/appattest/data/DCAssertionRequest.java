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

import com.webauthn4j.util.ArrayUtil;

import java.util.Arrays;

public class DCAssertionRequest {

    private byte[] credentialId;
    private byte[] authenticatorData;
    private byte[] clientDataHash;
    private byte[] signature;

    public DCAssertionRequest(byte[] credentialId, byte[] authenticatorData, byte[] clientDataHash, byte[] signature) {
        this.credentialId = ArrayUtil.clone(credentialId);
        this.authenticatorData = ArrayUtil.clone(authenticatorData);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
        this.signature = ArrayUtil.clone(signature);
    }

    public byte[] getCredentialId() {
        return ArrayUtil.clone(credentialId);
    }

    public byte[] getAuthenticatorData() {
        return ArrayUtil.clone(authenticatorData);
    }

    public byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    public byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DCAssertionRequest that = (DCAssertionRequest) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(clientDataHash, that.clientDataHash) &&
                Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
