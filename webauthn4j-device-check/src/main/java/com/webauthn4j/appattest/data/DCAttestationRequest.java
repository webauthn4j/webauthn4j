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

public class DCAttestationRequest {

    private byte[] attestationObject;
    private byte[] clientDataHash;

    public DCAttestationRequest(byte[] attestationObject, byte[] clientDataHash) {
        this.attestationObject = attestationObject;
        this.clientDataHash = clientDataHash;
    }

    public byte[] getAttestationObject() {
        return ArrayUtil.clone(attestationObject);
    }

    public byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DCAttestationRequest that = (DCAttestationRequest) o;
        return Arrays.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(clientDataHash, that.clientDataHash);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(attestationObject);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        return result;
    }
}
