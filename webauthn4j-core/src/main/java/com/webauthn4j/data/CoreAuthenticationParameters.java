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
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;
import java.util.Objects;

public class CoreAuthenticationParameters implements Serializable {

    private final CoreServerProperty serverProperty;
    private final CoreAuthenticator authenticator;

    // verification condition
    private final boolean userVerificationRequired;
    private final boolean userPresenceRequired;

    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        this.serverProperty = serverProperty;
        this.authenticator = authenticator;
        this.userVerificationRequired = userVerificationRequired;
        this.userPresenceRequired = userPresenceRequired;
    }

    public CoreAuthenticationParameters(
            @NonNull CoreServerProperty serverProperty,
            @NonNull CoreAuthenticator authenticator,
            boolean userVerificationRequired) {
        this(
                serverProperty,
                authenticator,
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

    public boolean isUserVerificationRequired() {
        return userVerificationRequired;
    }

    public boolean isUserPresenceRequired() {
        return userPresenceRequired;
    }


    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreAuthenticationParameters that = (CoreAuthenticationParameters) o;
        return userVerificationRequired == that.userVerificationRequired &&
                userPresenceRequired == that.userPresenceRequired &&
                Objects.equals(serverProperty, that.serverProperty) &&
                Objects.equals(authenticator, that.authenticator);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverProperty, authenticator, userVerificationRequired, userPresenceRequired);
    }
}
