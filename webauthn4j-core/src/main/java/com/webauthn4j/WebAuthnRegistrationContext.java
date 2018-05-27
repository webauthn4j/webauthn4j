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

package com.webauthn4j;

import com.webauthn4j.extension.ExtensionIdentifier;
import com.webauthn4j.server.ServerProperty;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * WebAuthnRegistrationContext
 */
public class WebAuthnRegistrationContext {

    // client property
    private final byte[] collectedClientData;
    private final byte[] attestationObject;
    private final byte[] clientExtensionOutputs;

    // server property
    private final ServerProperty serverProperty;

    // verification condition
    private boolean userVerificationRequired;
    private List<ExtensionIdentifier> expectedExtensions;

    public WebAuthnRegistrationContext(byte[] collectedClientData,
                                       byte[] attestationObject,
                                       byte[] clientExtensionOutputs,
                                       ServerProperty serverProperty,
                                       boolean userVerificationRequired,
                                       List<ExtensionIdentifier> expectedExtensions) {

        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.clientExtensionOutputs = clientExtensionOutputs;
        this.serverProperty = serverProperty;
        this.userVerificationRequired = userVerificationRequired;
        this.expectedExtensions = expectedExtensions;
    }

    public WebAuthnRegistrationContext(byte[] collectedClientData,
                                       byte[] attestationObject,
                                       ServerProperty serverProperty,
                                       boolean userVerificationRequired) {

        this(
                collectedClientData,
                attestationObject,
                null,
                serverProperty,
                userVerificationRequired,
                Collections.emptyList()
        );
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    public byte[] getClientExtensionOutputs() {
        return clientExtensionOutputs;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public List<ExtensionIdentifier> getExpectedExtensions() {
        return expectedExtensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationContext that = (WebAuthnRegistrationContext) o;
        return userVerificationRequired == that.userVerificationRequired &&
                Arrays.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(clientExtensionOutputs, that.clientExtensionOutputs) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(expectedExtensions, that.expectedExtensions);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(serverProperty, userVerificationRequired, expectedExtensions);
        result = 31 * result + Arrays.hashCode(collectedClientData);
        result = 31 * result + Arrays.hashCode(attestationObject);
        result = 31 * result + Arrays.hashCode(clientExtensionOutputs);
        return result;
    }
}
