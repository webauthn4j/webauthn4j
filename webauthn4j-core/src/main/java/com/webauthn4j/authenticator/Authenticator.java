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

package com.webauthn4j.authenticator;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Set;

/**
 * Core interface that represents WebAuthn authenticator
 */
public interface Authenticator extends CoreAuthenticator {

    /**
     * Returns the client extensions
     *
     * @return the client extensions
     */
    default @Nullable AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return null;
    }

    /**
     * Returns the {@link AuthenticatorTransport} {@link Set}
     *
     * @return the {@link AuthenticatorTransport} {@link Set}
     */
    @SuppressWarnings("squid:S1168")
    default @Nullable Set<AuthenticatorTransport> getTransports() {
        return null;
    }

}
