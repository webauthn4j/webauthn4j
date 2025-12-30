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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.core.type.TypeReference;

/**
 * Converter for {@link AuthenticationExtensionsClientOutputs}
 *
 * This class provides functionality to convert between AuthenticationExtensionsClientOutputs objects and their JSON string
 * representation for WebAuthn extensions processing.
 */
public class AuthenticationExtensionsClientOutputsConverter {

    // ~ Instance fields
    // ================================================================================================
    private final JsonConverter jsonConverter;

    // ~ Constructors
    // ================================================================================================

    /**
     * Creates a new AuthenticationExtensionsClientOutputsConverter instance.
     *
     * @param objectConverter converter for data serialization
     * @throws IllegalArgumentException if objectConverter is null
     */
    public AuthenticationExtensionsClientOutputsConverter(@NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");
        this.jsonConverter = objectConverter.getJsonConverter();
    }

    // ~ Methods
    // ================================================================================================

    /**
     * Converts a JSON string to an AuthenticationExtensionsClientOutputs object.
     *
     * @param value JSON string representation of authentication extensions client outputs
     * @param <T> the type of extension client output
     * @return the converted AuthenticationExtensionsClientOutputs object
     * @throws DataConversionException if conversion fails
     */
    public <T extends ExtensionClientOutput> @Nullable AuthenticationExtensionsClientOutputs<T> convert(@NotNull String value) {
        try {
            AssertUtil.notNull(value, "value must not be null");
            return jsonConverter.readValue(value, new TypeReference<AuthenticationExtensionsClientOutputs<T>>() {
            });
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts an AuthenticationExtensionsClientOutputs object to its JSON string representation.
     *
     * @param value the AuthenticationExtensionsClientOutputs object to convert
     * @param <T> the type of extension client output
     * @return JSON string representation of the AuthenticationExtensionsClientOutputs object
     * @throws DataConversionException if conversion fails
     */
    public <T extends ExtensionClientOutput> @NotNull String convertToString(@NotNull AuthenticationExtensionsClientOutputs<T> value) {
        try {
            AssertUtil.notNull(value, "value must not be null");
            return jsonConverter.writeValueAsString(value);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

}
