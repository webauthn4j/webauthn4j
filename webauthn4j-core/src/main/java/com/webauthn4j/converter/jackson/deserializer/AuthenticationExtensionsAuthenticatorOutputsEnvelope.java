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

package com.webauthn4j.converter.jackson.deserializer;

import com.webauthn4j.response.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.response.extension.authenticator.ExtensionAuthenticatorOutput;

public class AuthenticationExtensionsAuthenticatorOutputsEnvelope {

    private AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs;
    private int length;

    AuthenticationExtensionsAuthenticatorOutputsEnvelope(AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticationExtensionsAuthenticatorOutputs, int length) {
        this.authenticationExtensionsAuthenticatorOutputs = authenticationExtensionsAuthenticatorOutputs;
        this.length = length;
    }

    public AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> getAuthenticationExtensionsAuthenticatorOutputs() {
        return authenticationExtensionsAuthenticatorOutputs;
    }

    public int getLength() {
        return length;
    }
}
