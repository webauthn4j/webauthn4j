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

package com.webauthn4j.metadata.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.Base64Util;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;

public class MetadataAAGUIDRelaxedDeserializer extends StdDeserializer<AAGUID> {

    public MetadataAAGUIDRelaxedDeserializer() {
        super(AAGUID.class);
    }

    @Override
    public @NonNull AAGUID deserialize(@NonNull JsonParser p, @NonNull DeserializationContext ctxt) throws IOException {
        String value = p.getValueAsString();
        if(value.length() == 32){
            value = String.format("%s-%s-%s-%s-%s", value.substring(0, 8), value.substring(8, 12), value.substring(12, 16), value.substring(16, 20), value.substring(20, 32));
            return new AAGUID(value);
        }
        else if(value.length() == 36) {
            return new AAGUID(value);
        }
        else {
            return new AAGUID(Base64Util.decode(value));
        }
    }
}
