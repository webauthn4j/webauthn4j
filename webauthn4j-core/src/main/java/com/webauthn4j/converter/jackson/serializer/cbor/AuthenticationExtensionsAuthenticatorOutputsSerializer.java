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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class AuthenticationExtensionsAuthenticatorOutputsSerializer extends StdSerializer<AuthenticationExtensionsAuthenticatorOutputs<? extends ExtensionAuthenticatorOutput>> {

    public AuthenticationExtensionsAuthenticatorOutputsSerializer() {
        super(AuthenticationExtensionsAuthenticatorOutputs.class, false);
    }

    @Override
    public void serialize(AuthenticationExtensionsAuthenticatorOutputs<? extends ExtensionAuthenticatorOutput> value, JsonGenerator gen, SerializationContext provider) {

        List<String> keys = value.getKeys().stream().sorted(Comparator.comparing(String::length).thenComparing(String::compareTo)).collect(Collectors.toList());

        gen.writeStartObject(null, keys.size()); // This is important to write finite length map

        for (String key : keys) {
            gen.writeName(key);
            gen.writePOJO(value.getValue(key));
        }

        gen.writeEndObject();

    }
}
