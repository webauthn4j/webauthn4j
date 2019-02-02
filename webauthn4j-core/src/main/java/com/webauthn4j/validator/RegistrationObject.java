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

import com.webauthn4j.response.attestation.AttestationObject;
import com.webauthn4j.response.client.CollectedClientData;
import com.webauthn4j.server.ServerProperty;

import java.time.Clock;
import java.time.LocalDateTime;

/**
 * Internal data transfer object for registration data
 */
public class RegistrationObject {

    //~ Instance fields
    // ================================================================================================

    private final CollectedClientData collectedClientData;
    private final byte[] collectedClientDataBytes;
    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final byte[] authenticatorDataBytes;
    private final ServerProperty serverProperty;
    private final LocalDateTime timestamp;

    // ~ Constructor
    // ========================================================================================================

    public RegistrationObject(CollectedClientData collectedClientData,
                              byte[] collectedClientDataBytes,
                              AttestationObject attestationObject,
                              byte[] attestationObjectBytes,
                              byte[] authenticatorDataBytes,
                              ServerProperty serverProperty) {

        this(
                collectedClientData,
                collectedClientDataBytes,
                attestationObject,
                attestationObjectBytes,
                authenticatorDataBytes,
                serverProperty,
                LocalDateTime.now(Clock.systemUTC())
        );
    }

    public RegistrationObject(CollectedClientData collectedClientData,
                              byte[] collectedClientDataBytes,
                              AttestationObject attestationObject,
                              byte[] attestationObjectBytes,
                              byte[] authenticatorDataBytes,
                              ServerProperty serverProperty,
                              LocalDateTime timestamp) {

        this.collectedClientData = collectedClientData;
        this.collectedClientDataBytes = collectedClientDataBytes;
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = attestationObjectBytes;
        this.authenticatorDataBytes = authenticatorDataBytes;
        this.serverProperty = serverProperty;
        this.timestamp = timestamp;
    }

    // ~ Methods
    // ========================================================================================================

    public CollectedClientData getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getCollectedClientDataBytes() {
        return collectedClientDataBytes;
    }

    public AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public byte[] getAttestationObjectBytes() {
        return attestationObjectBytes;
    }

    public byte[] getAuthenticatorDataBytes() {
        return authenticatorDataBytes;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}
