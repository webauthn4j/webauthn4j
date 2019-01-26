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

import com.webauthn4j.util.WIP;

import java.util.Arrays;

@WIP
public class AuthenticatorAssertionResponse extends AuthenticatorResponse {

    // ~ Instance fields
    // ================================================================================================

    private byte[] authenticatorData;
    private byte[] signature;
    private byte[] userHandle;

    // ~ Constructor
    // ========================================================================================================

    public AuthenticatorAssertionResponse(byte[] clientDataJSON, byte[] authenticatorData, byte[] signature, byte[] userHandle) {
        super(clientDataJSON);
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.userHandle = userHandle;
    }

    /**
     * default constructor for jackson deserialization
     */
    public AuthenticatorAssertionResponse() {
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorAssertionResponse that = (AuthenticatorAssertionResponse) o;
        return Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature) &&
                Arrays.equals(userHandle, that.userHandle);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        result = 31 * result + Arrays.hashCode(userHandle);
        return result;
    }
}
