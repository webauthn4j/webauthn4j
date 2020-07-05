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

package com.webauthn4j.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;

/**
 * Converter for {@link AuthenticationExtensionsClientOutputs}
 */
public class AuthenticationExtensionsClientOutputsConverter {

    // ~ Instance fields
    // ================================================================================================
    private final JsonConverter jsonConverter;

    // ~ Constructors
    // ================================================================================================

    public AuthenticationExtensionsClientOutputsConverter(ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    // ~ Methods
    // ================================================================================================

    public <T extends ExtensionClientOutput> AuthenticationExtensionsClientOutputs<T> convert(String value) {
        if (value == null) {
            return null;
        }
        return jsonConverter.readValue(value, new TypeReference<AuthenticationExtensionsClientOutputs<T>>(){});
    }

    public <T extends ExtensionClientOutput> String convertToString(AuthenticationExtensionsClientOutputs<T> value) {
        if (value == null) {
            return null;
        }
        return jsonConverter.writeValueAsString(value);
    }

}
