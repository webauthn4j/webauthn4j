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

package com.webauthn4j.data;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.CollectionUtil;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

public class WebAuthnAuthenticationParameters {

    private final ServerProperty serverProperty;
    private final Authenticator authenticator;

    // verification condition
    private final LocalDateTime timestamp;
    private boolean userVerificationRequired;
    private boolean userPresenceRequired;
    private List<String> expectedExtensionIds;

    public WebAuthnAuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            LocalDateTime timestamp,
            boolean userVerificationRequired,
            boolean userPresenceRequired,
            List<String> expectedExtensionIds) {
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
        this.timestamp = timestamp;
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
        this.expectedExtensionIds = CollectionUtil.unmodifiableList(expectedExtensionIds);
    }

    public WebAuthnAuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired,
            List<String> expectedExtensionIds) {
        this(
                serverProperty,
                authenticator,
                LocalDateTime.now(),
                userVerificationRequired,
                userPresenceRequired,
                expectedExtensionIds
        );
    }

    public WebAuthnAuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        this(
                serverProperty,
                authenticator,
                userVerificationRequired,
                userPresenceRequired,
                null
        );
    }

    public WebAuthnAuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            boolean userVerificationRequired) {
        this(
                serverProperty,
                authenticator,
                userVerificationRequired,
                true
        );
    }

    public ServerProperty getServerProperty() {
        return serverProperty;
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
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
        WebAuthnAuthenticationParameters that = (WebAuthnAuthenticationParameters) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(authenticator, that.authenticator) &&
                Objects.equals(timestamp, that.timestamp) &&
                Objects.equals(expectedExtensionIds, that.expectedExtensionIds);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverProperty, authenticator, timestamp, userVerificationRequired, userPresenceRequired, expectedExtensionIds);
    }
}