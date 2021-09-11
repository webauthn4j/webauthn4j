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

package com.webauthn4j.converter.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;

import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public class AuthenticationExtensionsAuthenticatorOutputsSerializer extends StdSerializer<AuthenticationExtensionsAuthenticatorOutputs<? extends ExtensionAuthenticatorOutput>> {

    public AuthenticationExtensionsAuthenticatorOutputsSerializer() {
        super(AuthenticationExtensionsAuthenticatorOutputs.class, false);
    }

    @Override
    public void serialize(AuthenticationExtensionsAuthenticatorOutputs<? extends ExtensionAuthenticatorOutput> value, JsonGenerator gen, SerializerProvider provider) throws IOException {

        List<String> keys = value.getKeys().stream().sorted(Comparator.comparing(String::length).thenComparing(String::compareTo)).collect(Collectors.toList());

        ((CBORGenerator) gen).writeStartObject(keys.size()); // This is important to write finite length map

        for (String key : keys) {
            gen.writeFieldName(key);
            gen.writeObject(value.getValue(key));
        }

        gen.writeEndObject();

    }
}
