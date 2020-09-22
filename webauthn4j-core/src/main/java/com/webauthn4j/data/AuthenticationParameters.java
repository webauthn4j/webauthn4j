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

public class AuthenticationParameters extends CoreAuthenticationParameters {

    public AuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            boolean userVerificationRequired,
            boolean userPresenceRequired) {
        super(serverProperty, authenticator, userVerificationRequired, userPresenceRequired);
    }

    public AuthenticationParameters(
            ServerProperty serverProperty,
            Authenticator authenticator,
            boolean userVerificationRequired) {
        super(
                serverProperty,
                authenticator,
                userVerificationRequired,
                true
        );
    }

    @Override
    public ServerProperty getServerProperty() {
        return (ServerProperty) super.getServerProperty();
    }

    @Override
    public Authenticator getAuthenticator() {
        return (Authenticator) super.getAuthenticator();
    }

}
