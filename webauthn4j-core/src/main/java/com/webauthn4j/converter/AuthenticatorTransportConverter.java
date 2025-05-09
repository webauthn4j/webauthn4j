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
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Converter for {@link AuthenticatorTransport}
 *
 * This class provides functionality to convert between AuthenticatorTransport objects and their string
 * representation for WebAuthn processing.
 */
public class AuthenticatorTransportConverter {

    /**
     * Converts a string to an AuthenticatorTransport object.
     *
     * @param value the string representation of authenticator transport
     * @return the converted AuthenticatorTransport object
     * @throws DataConversionException if conversion fails
     */
    public @NotNull AuthenticatorTransport convert(@NotNull String value) {
        try {
            AssertUtil.notNull(value, "value must not be null");
            return AuthenticatorTransport.create(value);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts a set of strings to a set of AuthenticatorTransport objects.
     *
     * @param values the set of string representations of authenticator transports
     * @return the set of converted AuthenticatorTransport objects
     * @throws DataConversionException if conversion fails
     */
    @SuppressWarnings("squid:S1168")
    public @NotNull Set<AuthenticatorTransport> convertSet(@NotNull Set<String> values) {
        try {
            AssertUtil.notNull(values, "values must not be null");
            return values.stream().map(this::convert).collect(Collectors.toSet());
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts an AuthenticatorTransport object to its string representation.
     *
     * @param value the AuthenticatorTransport object to convert
     * @return string representation of the AuthenticatorTransport object
     * @throws DataConversionException if conversion fails
     */
    public @NotNull String convertToString(@NotNull AuthenticatorTransport value) {
        try {
            AssertUtil.notNull(value, "value must not be null");
            return value.getValue();
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    /**
     * Converts a set of AuthenticatorTransport objects to a set of strings.
     *
     * @param values the set of AuthenticatorTransport objects to convert
     * @return the set of string representations of the AuthenticatorTransport objects
     * @throws DataConversionException if conversion fails
     */
    @SuppressWarnings("squid:S1168")
    public @NotNull Set<String> convertSetToStringSet(@NotNull Set<AuthenticatorTransport> values) {
        try {
            AssertUtil.notNull(values, "values must not be null");
            return values.stream().map(this::convertToString).collect(Collectors.toSet());
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

}
