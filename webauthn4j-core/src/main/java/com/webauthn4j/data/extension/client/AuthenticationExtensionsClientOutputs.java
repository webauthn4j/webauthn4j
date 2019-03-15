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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.webauthn4j.util.AbstractImmutableMap;

import java.util.Collections;
import java.util.Map;

/**
 * Map containing the client extension output values for zero or more WebAuthn
 * extensions, as defined in §9 WebAuthn Extensions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticationextensionsclientoutputs">§5.8. Authentication Extensions Client Outputs</a>
 */
public class AuthenticationExtensionsClientOutputs<V extends ExtensionClientOutput> extends AbstractImmutableMap<String, V> {

    @JsonCreator
    public AuthenticationExtensionsClientOutputs(Map<String, V> map) {
        super(map);
    }

    public AuthenticationExtensionsClientOutputs(){
        this(Collections.emptyMap());
    }

}
