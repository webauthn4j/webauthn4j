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

package com.webauthn4j.data.extension.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AbstractImmutableMap;

import java.util.Collections;
import java.util.Map;

/**
 * {@link AuthenticationExtensionsAuthenticatorInputs} containing the authenticator extension input values for
 * zero or more WebAuthn extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#typedefdef-authenticationextensionsauthenticatorinputs">
 * §5.9. Authentication Extensions Authenticator Inputs (typedef AuthenticationExtensionsAuthenticatorInputs)</a>
 */
public class AuthenticationExtensionsAuthenticatorInputs<V extends ExtensionAuthenticatorInput> extends AbstractImmutableMap<String, V> {

    @JsonCreator
    public AuthenticationExtensionsAuthenticatorInputs(Map<String, V> map) {
        super(map);
    }

    public AuthenticationExtensionsAuthenticatorInputs() {
        this(Collections.emptyMap());
    }

}