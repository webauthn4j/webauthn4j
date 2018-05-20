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

import com.webauthn4j.server.ServerProperty;

import java.util.Arrays;
import java.util.Objects;

/**
 * WebAuthnRegistrationContext
 */
public class WebAuthnRegistrationContext {

    private final byte[] collectedClientData;
    private final byte[] attestationObject;

    private final ServerProperty serverProperty;

    public WebAuthnRegistrationContext(byte[] collectedClientData,
                                       byte[] attestationObject,
                                       ServerProperty serverProperty) {

        this.collectedClientData = collectedClientData;
        this.attestationObject = attestationObject;
        this.serverProperty = serverProperty;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public byte[] getAttestationObject() {
        return attestationObject;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnRegistrationContext that = (WebAuthnRegistrationContext) o;
        return Arrays.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(attestationObject, that.attestationObject) &&
                Objects.equals(serverProperty, that.serverProperty);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(serverProperty);
        result = 31 * result + Arrays.hashCode(collectedClientData);
        result = 31 * result + Arrays.hashCode(attestationObject);
        return result;
    }
}
