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

import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;


/**
 * WebAuthn abstract base context
 */
abstract class AbstractWebAuthnContext implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    // user inputs
    private final byte[] clientDataJSON;
    private final String clientExtensionsJSON;

    // server property
    private final ServerProperty serverProperty;

    // verification condition
    private boolean userVerificationRequired;
    private boolean userPresenceRequired;
    private List<String> expectedExtensionIds;

    // ~ Constructor
    // ========================================================================================================

    AbstractWebAuthnContext(
            byte[] clientDataJSON,
            String clientExtensionsJSON,
            ServerProperty serverProperty,
            boolean userVerificationRequired,
            boolean userPresenceRequired,
            List<String> expectedExtensionIds) {
        this.clientDataJSON = clientDataJSON;
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.serverProperty = serverProperty;
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
        this.expectedExtensionIds = CollectionUtil.unmodifiableList(expectedExtensionIds);
    }

    public byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    public String getClientExtensionsJSON() {
        return clientExtensionsJSON;
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public boolean isUserPresenceRequired() {
        return userPresenceRequired;
    }

    public List<String> getExpectedExtensionIds() {
        return expectedExtensionIds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractWebAuthnContext that = (AbstractWebAuthnContext) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(expectedExtensionIds, that.expectedExtensionIds);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(clientExtensionsJSON, serverProperty, userVerificationRequired, userPresenceRequired, expectedExtensionIds);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        return result;
    }
}
