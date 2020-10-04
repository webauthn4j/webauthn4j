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
            AttestationObject attestationObject,
            byte[] attestationObjectBytes,
            byte[] clientDataHash,
            CoreServerProperty serverProperty,
            Instant timestamp) {
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.clientDataHash = clientDataHash;
        this.serverProperty = serverProperty;
        this.timestamp = timestamp;
    }

    public CoreRegistrationObject(
            AttestationObject attestationObject,
            byte[] attestationObjectBytes,
            byte[] clientDataHash,
            CoreServerProperty serverProperty) {

        this(attestationObject, attestationObjectBytes, clientDataHash, serverProperty, Instant.now());
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return ArrayUtil.clone(attestationObjectBytes);
    }


    public byte[] getAuthenticatorDataBytes() {
        return extractAuthenticatorData(attestationObjectBytes);
    }

    public byte[] getClientDataHash() {
        return clientDataHash;
    }

    public CoreServerProperty getServerProperty() {
        return serverProperty;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
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


    private static byte[] extractAuthenticatorData(byte[] attestationObject) {
        return JacksonUtil.binaryValue(JacksonUtil.readTree(cborMapper, attestationObject).get("authData"));
    }
}
