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

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/**
 * Internal data transfer object for registration data
 */
public class RegistrationObject implements Serializable {

    //~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final byte[] authenticatorDataBytes;
    private final Set<AuthenticatorTransport> transports;
    private final AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private final ServerProperty serverProperty;
    private final LocalDateTime timestamp;

    // ~ Constructor
    // ========================================================================================================
    @SuppressWarnings("squid:S00107")
    public RegistrationObject(CollectedClientData collectedClientData,
                              byte[] collectedClientDataBytes,
                              AttestationObject attestationObject,
                              byte[] attestationObjectBytes,
                              byte[] authenticatorDataBytes,
                              Set<AuthenticatorTransport> transports,
                              AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
                              ServerProperty serverProperty) {

        this(
                collectedClientData,
                collectedClientDataBytes,
                attestationObject,
                attestationObjectBytes,
                authenticatorDataBytes,
                transports,
                clientExtensions,
                serverProperty,
                LocalDateTime.now(Clock.systemUTC())
        );
    }

    @SuppressWarnings("squid:S00107")
    public RegistrationObject(CollectedClientData collectedClientData,
                              byte[] collectedClientDataBytes,
                              AttestationObject attestationObject,
                              byte[] attestationObjectBytes,
                              byte[] authenticatorDataBytes,
                              Set<AuthenticatorTransport> transports,
                              AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
                              ServerProperty serverProperty,
                              LocalDateTime timestamp) {

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.transports = CollectionUtil.unmodifiableSet(transports);
        this.clientExtensions = clientExtensions;
        this.serverProperty = serverProperty;
        this.timestamp = timestamp;
    }

    // ~ Methods
    // ========================================================================================================

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return ArrayUtil.clone(attestationObjectBytes);
    }

    public byte[] getAuthenticatorDataBytes() {
        return ArrayUtil.clone(authenticatorDataBytes);
    }

    public Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    public AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RegistrationObject that = (RegistrationObject) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(attestationObjectBytes, that.attestationObjectBytes) &&
                Arrays.equals(authenticatorDataBytes, that.authenticatorDataBytes) &&
                Objects.equals(transports, that.transports) &&
                Objects.equals(clientExtensions, that.clientExtensions) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(timestamp, that.timestamp);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(collectedClientData, attestationObject, transports, clientExtensions, serverProperty, timestamp);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        result = 31 * result + Arrays.hashCode(attestationObjectBytes);
        result = 31 * result + Arrays.hashCode(authenticatorDataBytes);
        return result;
    }
}
