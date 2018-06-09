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
import java.util.List;
import java.util.Objects;


/**
 * AbstractWebAuthnContext
 */
class AbstractWebAuthnContext {

    //~ Instance fields ================================================================================================

    // user inputs
    private final byte[] clientDataJSON;
    private final String clientExtensionsJSON;

    // server property
    private final ServerProperty serverProperty;

    // verification condition
    private boolean userVerificationRequired;
    private List<String> expectedExtensionIds;

    public AbstractWebAuthnContext(
            byte[] clientDataJSON,
            String clientExtensionsJSON,
            ServerProperty serverProperty,
            boolean userVerificationRequired,
            List<String> expectedExtensionIds) {
        this.clientDataJSON = clientDataJSON;
        this.clientExtensionsJSON = clientExtensionsJSON;
        this.serverProperty = serverProperty;
        this.userVerificationRequired = userVerificationRequired;
        this.expectedExtensionIds = expectedExtensionIds;
    }

    public byte[] getClientDataJSON() {
        return clientDataJSON;
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

    public List<String> getExpectedExtensionIds() {
        return expectedExtensionIds;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractWebAuthnContext that = (AbstractWebAuthnContext) o;
        return userVerificationRequired == that.userVerificationRequired &&
                Arrays.equals(clientDataJSON, that.clientDataJSON) &&
                Objects.equals(clientExtensionsJSON, that.clientExtensionsJSON) &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(expectedExtensionIds, that.expectedExtensionIds);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(clientExtensionsJSON, serverProperty, userVerificationRequired, expectedExtensionIds);
        result = 31 * result + Arrays.hashCode(clientDataJSON);
        return result;
    }
}
