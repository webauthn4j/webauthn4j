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
public class AuthenticatorAttestationResponse extends AuthenticatorResponse {

    // ~ Instance fields
    // ================================================================================================

    private byte[] attestationObject;

    // ~ Constructor
    // ========================================================================================================

    public AuthenticatorAttestationResponse(byte[] clientDataJSON,
                                            byte[] attestationObject) {
        super(clientDataJSON);
        this.attestationObject = attestationObject;
    }

    /**
     * default constructor for jackson deserialization
     */
    public AuthenticatorAttestationResponse() {
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorAttestationResponse that = (AuthenticatorAttestationResponse) o;
        return Arrays.equals(attestationObject, that.attestationObject);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(attestationObject);
    }
}
