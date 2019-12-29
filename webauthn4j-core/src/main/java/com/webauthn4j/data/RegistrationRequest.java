/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.data;

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.CollectionUtil;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

public class RegistrationRequest {

    // ~ Instance fields
    // ================================================================================================

    // user inputs
    private final byte[] attestationObject;
    private final byte[] clientDataJSON;
    private final String clientExtensionsJSON;
    private final Set<String> transports;

    public RegistrationRequest(byte[] attestationObject, byte[] clientDataJSON, String clientExtensionsJSON, Set<String> transports) {
        this.attestationObject = ArrayUtil.clone(attestationObject);
        this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.transports = CollectionUtil.unmodifiableSet(transports);
    }

    public RegistrationRequest(byte[] attestationObject, byte[] clientDataJSON, String clientExtensionsJSON) {
        this(attestationObject, clientDataJSON, clientExtensionsJSON, null);
    }

    public RegistrationRequest(byte[] attestationObject, byte[] clientDataJSON, Set<String> transports) {
        this(attestationObject, clientDataJSON, null, transports);
    }

    public RegistrationRequest(byte[] attestationObject, byte[] clientDataJSON) {
        this(attestationObject, clientDataJSON, null, null);
    }

    public byte[] getAttestationObject() {
        return ArrayUtil.clone(attestationObject);
    }

    public byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public Set<String> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegistrationRequest that = (RegistrationRequest) o;
        return Arrays.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(clientExtensionsJSON, transports);
        result = 31 * result + Arrays.hashCode(attestationObject);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        return result;
    }
}
