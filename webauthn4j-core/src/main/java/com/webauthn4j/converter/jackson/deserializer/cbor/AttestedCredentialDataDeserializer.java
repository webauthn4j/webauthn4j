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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;

public class AttestedCredentialDataDeserializer extends StdDeserializer<AttestedCredentialData> {

    private final AttestedCredentialDataConverter attestedCredentialDataConverter;

    public AttestedCredentialDataDeserializer(@NonNull ObjectConverter objectConverter) {
        super(AttestedCredentialData.class);
        attestedCredentialDataConverter = new AttestedCredentialDataConverter(objectConverter);
    }

    @Override
    public @NonNull AttestedCredentialData deserialize(@NonNull JsonParser p, @NonNull DeserializationContext ctxt) throws IOException {
        byte[] value = p.getBinaryValue();
        return attestedCredentialDataConverter.convert(value);
    }
}
