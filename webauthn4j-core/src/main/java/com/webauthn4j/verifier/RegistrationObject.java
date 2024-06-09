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

package com.webauthn4j.verifier;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import com.webauthn4j.util.MessageDigestUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/**
 * Internal data transfer object for registration data
 */
public class RegistrationObject extends CoreRegistrationObject {

    //~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;
    private final Set<AuthenticatorTransport> transports;

    // ~ Constructor
    // ========================================================================================================
    @SuppressWarnings("squid:S00107")
    public RegistrationObject(
            @NotNull AttestationObject attestationObject,
            @NotNull byte[] attestationObjectBytes,
            @NotNull CollectedClientData collectedClientData,
            @NotNull byte[] collectedClientDataBytes,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports,
            @NotNull ServerProperty serverProperty,
            @NotNull Instant timestamp) {

        super(attestationObject, attestationObjectBytes, MessageDigestUtil.createSHA256().digest(collectedClientDataBytes), serverProperty, timestamp);

        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(collectedClientDataBytes, "collectedClientDataBytes must not be null");

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = ArrayUtil.clone(collectedClientDataBytes);
        this.clientExtensions = clientExtensions;
        this.transports = CollectionUtil.unmodifiableSet(transports);
    }

    public RegistrationObject(
            @NotNull AttestationObject attestationObject,
            @NotNull byte[] attestationObjectBytes,
            @NotNull CollectedClientData collectedClientData,
            @NotNull byte[] collectedClientDataBytes,
            @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
            @Nullable Set<AuthenticatorTransport> transports,
            @NotNull ServerProperty serverProperty) {

        this(attestationObject, attestationObjectBytes, collectedClientData, collectedClientDataBytes, clientExtensions, transports, serverProperty, Instant.now());
    }

    // ~ Methods
    // ========================================================================================================

    public @NotNull CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public @NotNull byte[] getCollectedClientDataBytes() {
        return ArrayUtil.clone(collectedClientDataBytes);
    }

    public @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    public @Nullable Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public @NotNull ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RegistrationObject that = (RegistrationObject) o;
        return Objects.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(collectedClientDataBytes, that.collectedClientDataBytes) &&
                Objects.equals(clientExtensions, that.clientExtensions) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), collectedClientData, clientExtensions, transports);
        result = 31 * result + Arrays.hashCode(collectedClientDataBytes);
        return result;
    }
}

