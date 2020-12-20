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

package com.webauthn4j.validator;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.jackson.JacksonUtil;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public class CoreRegistrationObject {

    private static final ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());

    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final byte[] clientDataHash;
    private final CoreServerProperty serverProperty;
    private final Instant timestamp;

    public CoreRegistrationObject(
            @NonNull AttestationObject attestationObject,
            @NonNull byte[] attestationObjectBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty,
            @NonNull Instant timestamp) {

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
            @NonNull AttestationObject attestationObject,
            @NonNull byte[] attestationObjectBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty) {

        this(attestationObject, attestationObjectBytes, clientDataHash, serverProperty, Instant.now());
    }

    private static @NonNull byte[] extractAuthenticatorData(@NonNull byte[] attestationObject) {
        return JacksonUtil.binaryValue(JacksonUtil.readTree(cborMapper, attestationObject).get("authData"));
    }

    public @NonNull AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public @NonNull byte[] getAttestationObjectBytes() {
        return ArrayUtil.clone(attestationObjectBytes);
    }

    public @NonNull byte[] getAuthenticatorDataBytes() {
        return extractAuthenticatorData(attestationObjectBytes);
    }

    public @NonNull byte[] getClientDataHash() {
        return clientDataHash;
    }

    public @NonNull CoreServerProperty getServerProperty() {
        return serverProperty;
    }

    public @NonNull Instant getTimestamp() {
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
