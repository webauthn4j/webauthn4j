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

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.data.AuthenticatorTransport;

import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticatorTransportConverter {

    public AuthenticatorTransport convert(String value) {
        try {
            return AuthenticatorTransport.create(value);
        } catch (IllegalArgumentException e) {
            throw new DataConversionException(e);
        }
    }

    @SuppressWarnings("squid:S1168")
    public Set<AuthenticatorTransport> convertSet(Set<String> values) {
        if (values == null) {
            return null;
        }
        return values.stream().map(this::convert).collect(Collectors.toSet());
    }

    public String convertToString(AuthenticatorTransport value) {
        return value.getValue();
    }

    @SuppressWarnings("squid:S1168")
    public Set<String> convertSetToStringSet(Set<AuthenticatorTransport> values) {
        if (values == null) {
            return null;
        }
        return values.stream().map(this::convertToString).collect(Collectors.toSet());
    }

}
