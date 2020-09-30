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

import java.util.Arrays;

public class DCAssertionRequest {

    private byte[] credentialId;
    private byte[] assertion;
    private byte[] clientDataHash;

    public DCAssertionRequest(byte[] credentialId, byte[] assertion, byte[] clientDataHash) {
        this.credentialId = credentialId;
        this.assertion = assertion;
        this.clientDataHash = clientDataHash;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public byte[] getAssertion() {
        return assertion;
    }

    public void setAssertion(byte[] assertion) {
        this.assertion = assertion;
    }

    public byte[] getClientDataHash() {
        return clientDataHash;
    }

    public void setClientDataHash(byte[] clientDataHash) {
        this.clientDataHash = clientDataHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DCAssertionRequest that = (DCAssertionRequest) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(assertion, that.assertion) &&
                Arrays.equals(clientDataHash, that.clientDataHash);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(assertion);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        return result;
    }
}
