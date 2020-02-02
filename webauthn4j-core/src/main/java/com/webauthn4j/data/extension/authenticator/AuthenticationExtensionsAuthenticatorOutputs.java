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

package com.webauthn4j.data.extension.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.data.AbstractImmutableMap;

import java.util.Collections;
import java.util.Map;

public class AuthenticationExtensionsAuthenticatorOutputs<V extends ExtensionAuthenticatorOutput> extends AbstractImmutableMap<String, V> {

    @JsonCreator
    public AuthenticationExtensionsAuthenticatorOutputs(Map<String, V> map) {
        super(map);
    }

    public AuthenticationExtensionsAuthenticatorOutputs() {
        this(Collections.emptyMap());
    }

}
