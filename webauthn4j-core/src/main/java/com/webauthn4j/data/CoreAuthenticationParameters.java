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

package com.webauthn4j.data;

import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;
import java.util.Objects;

public class CoreAuthenticationParameters {

    private final CoreServerProperty serverProperty;
    private final CoreAuthenticator authenticator;

    // verification condition
    private final List<byte[]> allowCredentials;
    private final boolean userVerificationRequired;
    private final boolean userPresenceRequired;

    /**
     * {@link CoreAuthenticationParameters} constructor
     * @param serverProperty server property
     * @param allowCredentials allowed credentialId list. If all credentialId(s) are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     * @param userPresenceRequired true if user presence is required. Otherwise, false
     */
    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            @Nullable List<byte[]> allowCredentials,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");
        AssertUtil.notNull(authenticator, "authenticator must not be null");
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
        this.allowCredentials = CollectionUtil.unmodifiableList(allowCredentials);
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
    }

    /**
     * {@link CoreAuthenticationParameters} constructor
     * @param serverProperty server property
     * @param allowCredentials allowed credentialId list. If all credentialId(s) are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     */
    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            @Nullable List<byte[]> allowCredentials,
            boolean userVerificationRequired) {
        this(
                serverProperty,
                authenticator,
                allowCredentials,
                userVerificationRequired,
                true
        );
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        this(
                serverProperty,
                authenticator,
                null,
                userVerificationRequired,
                userPresenceRequired
        );
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            boolean userVerificationRequired) {
        this(
                serverProperty,
                authenticator,
                null,
                userVerificationRequired,
                true
        );
    }

    public @NonNull CoreServerProperty getServerProperty() {
        return serverProperty;
    }

    public @NonNull CoreAuthenticator getAuthenticator() {
        return authenticator;
    }

    public @Nullable List<byte[]> getAllowCredentials() {
        return allowCredentials;
    }

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public boolean isUserPresenceRequired() {
        return userPresenceRequired;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreAuthenticationParameters that = (CoreAuthenticationParameters) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(authenticator, that.authenticator) &&
                Objects.equals(allowCredentials, that.allowCredentials);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverProperty, authenticator, allowCredentials, userVerificationRequired, userPresenceRequired);
    }

    @Override
    public String toString() {
        return "CoreAuthenticationParameters(" +
                "serverProperty=" + serverProperty +
                ", authenticator=" + authenticator +
                ", allowCredentials=" + allowCredentials +
                ", userVerificationRequired=" + userVerificationRequired +
                ", userPresenceRequired=" + userPresenceRequired +
                ')';
    }
}
