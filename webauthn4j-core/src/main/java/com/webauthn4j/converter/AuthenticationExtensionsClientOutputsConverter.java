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

package com.webauthn4j.converter;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;

public class AuthenticationExtensionsClientOutputsConverter {

    //~ Instance fields
    // ================================================================================================
    private JsonConverter jsonConverter;

    //~ Constructors
    // ================================================================================================

    public AuthenticationExtensionsClientOutputsConverter(JsonConverter jsonConverter) {
        this.jsonConverter = jsonConverter;
    }

    //~ Methods
    // ================================================================================================

    public AuthenticationExtensionsClientOutputs<ExtensionClientOutput> convert(String value) {
        if (value == null) {
            return null;
        }
        return jsonConverter.readValue(value, AuthenticationExtensionsClientOutputs.class);
    }

    public String convertToString(AuthenticationExtensionsClientOutputs value) {
        if (value == null) {
            return null;
        }
        return jsonConverter.writeValueAsString(value);
    }
}
