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
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticatorTransportConverter {

    public @NonNull AuthenticatorTransport convert(@NonNull String value) {
        AssertUtil.notNull(value, "value must not be null");
        try {
            return AuthenticatorTransport.create(value);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    @SuppressWarnings("squid:S1168")
    public @NonNull Set<AuthenticatorTransport> convertSet(@NonNull Set<String> values) {
        AssertUtil.notNull(values, "values must not be null");
        return values.stream().map(this::convert).collect(Collectors.toSet());
    }

    public @NonNull String convertToString(@NonNull AuthenticatorTransport value) {
        AssertUtil.notNull(value, "value must not be null");
        return value.getValue();
    }

    @SuppressWarnings("squid:S1168")
    public @NonNull Set<String> convertSetToStringSet(@NonNull Set<AuthenticatorTransport> values) {
        AssertUtil.notNull(values, "values must not be null");
        return values.stream().map(this::convertToString).collect(Collectors.toSet());
    }

}
