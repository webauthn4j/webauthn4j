/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import org.checkerframework.checker.nullness.qual.Nullable;

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

    public RegistrationRequest(
            @Nullable byte[] attestationObject,
            @Nullable byte[] clientDataJSON,
            @Nullable String clientExtensionsJSON,
            @Nullable Set<String> transports) {
        this.attestationObject = ArrayUtil.clone(attestationObject);
        this.clientDataJSON = ArrayUtil.clone(clientDataJSON);
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.transports = CollectionUtil.unmodifiableSet(transports);
    }

    public RegistrationRequest(
            @Nullable byte[] attestationObject,
            @Nullable byte[] clientDataJSON,
            @Nullable String clientExtensionsJSON) {
        this(attestationObject, clientDataJSON, clientExtensionsJSON, null);
    }

    public RegistrationRequest(
            @Nullable byte[] attestationObject,
            @Nullable byte[] clientDataJSON,
            @Nullable Set<String> transports) {
        this(attestationObject, clientDataJSON, null, transports);
    }

    public RegistrationRequest(
            @Nullable byte[] attestationObject,
            @Nullable byte[] clientDataJSON) {
        this(attestationObject, clientDataJSON, null, null);
    }

    public @Nullable byte[] getAttestationObject() {
        return ArrayUtil.clone(attestationObject);
    }

    public @Nullable byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    public @Nullable String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public @Nullable Set<String> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(@Nullable Object o) {
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

    @Override
    public String toString() {
        return "RegistrationRequest{" +
                "attestationObject=" + ArrayUtil.toHexString(attestationObject) +
                ", clientDataJSON=" + ArrayUtil.toHexString(clientDataJSON) +
                ", clientExtensionsJSON=" + clientExtensionsJSON +
                ", transports=" + transports +
                '}';
    }
}
