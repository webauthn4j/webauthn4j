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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.server.ServerProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;

public class AuthenticationParameters extends CoreAuthenticationParameters {

    /**
     * {@link AuthenticationParameters} constructor
     * @param serverProperty server property
     * @param allowCredentials allowed credentialId list. If all credentialId(s) are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     * @param userPresenceRequired true if user presence is required. Otherwise, false
     */
    public AuthenticationParameters(@NonNull ServerProperty serverProperty, @NonNull Authenticator authenticator, @Nullable List<byte[]> allowCredentials, boolean userVerificationRequired, boolean userPresenceRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired, userPresenceRequired);
    }

    /**
     * {@link AuthenticationParameters} constructor
     * @param serverProperty server property
     * @param allowCredentials allowed credentialId list. If all credentialId(s) are allowed, pass null
     * @param userVerificationRequired true if user verification is required. Otherwise, false
     */
    public AuthenticationParameters(@NonNull ServerProperty serverProperty, @NonNull Authenticator authenticator, @Nullable List<byte[]> allowCredentials, boolean userVerificationRequired) {
        super(serverProperty, authenticator, allowCredentials, userVerificationRequired);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public AuthenticationParameters(
            @NonNull ServerProperty serverProperty,
            @NonNull Authenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        super(serverProperty, authenticator, userVerificationRequired, userPresenceRequired);
    }

    /**
     * @deprecated Deprecated as pubKeyCredParams verification was introduced from WebAuthn Level2.
     */
    @SuppressWarnings("squid:S1133")
    @Deprecated
    public AuthenticationParameters(
            @NonNull ServerProperty serverProperty,
            @NonNull Authenticator authenticator,
            boolean userVerificationRequired) {
        super(
                serverProperty,
                authenticator,
                userVerificationRequired,
                true
        );
    }

    @Override
    public @NonNull ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public @NonNull Authenticator getAuthenticator() {
        return (Authenticator) super.getAuthenticator();
    }

}
