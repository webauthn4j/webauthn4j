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

package com.webauthn4j.verifier;

import com.webauthn4j.converter.jackson.JacksonUtil;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public class CoreRegistrationObject {

    private static final CBORMapper cborMapper = new CBORMapper();

    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final byte[] clientDataHash;
    private final CoreServerProperty serverProperty;
    private final Instant timestamp;

    public CoreRegistrationObject(
            @NotNull AttestationObject attestationObject,
            @NotNull byte[] attestationObjectBytes,
            @NotNull byte[] clientDataHash,
            @NotNull CoreServerProperty serverProperty,
            @NotNull Instant timestamp) {

        AssertUtil.notNull(attestationObject, "attestationObject must not be null");
        AssertUtil.notNull(attestationObjectBytes, "attestationObjectBytes must not be null");
        AssertUtil.notNull(clientDataHash, "clientDataHash must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        AssertUtil.notNull(timestamp, "timestamp must not be null");

        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.clientDataHash = clientDataHash;
        this.serverProperty = serverProperty;
        this.timestamp = timestamp;
    }

    public CoreRegistrationObject(
            @NotNull AttestationObject attestationObject,
            @NotNull byte[] attestationObjectBytes,
            @NotNull byte[] clientDataHash,
            @NotNull CoreServerProperty serverProperty) {

        this(attestationObject, attestationObjectBytes, clientDataHash, serverProperty, Instant.now());
    }

    private static @NotNull byte[] extractAuthenticatorData(@NotNull byte[] attestationObject) {
        return JacksonUtil.binaryValue(JacksonUtil.readTree(cborMapper, attestationObject).get("authData"));
    }

    public @NotNull AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public @NotNull byte[] getAttestationObjectBytes() {
        return ArrayUtil.clone(attestationObjectBytes);
    }

    public @NotNull byte[] getAuthenticatorDataBytes() {
        return extractAuthenticatorData(attestationObjectBytes);
    }

    public @NotNull byte[] getClientDataHash() {
        return clientDataHash;
    }

    public @NotNull CoreServerProperty getServerProperty() {
        return serverProperty;
    }

    public @NotNull Instant getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreRegistrationObject that = (CoreRegistrationObject) o;
        return Objects.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(attestationObjectBytes, that.attestationObjectBytes) &&
                Arrays.equals(clientDataHash, that.clientDataHash) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(attestationObject, serverProperty, timestamp);
        result = 31 * result + Arrays.hashCode(attestationObjectBytes);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        return result;
    }
}
