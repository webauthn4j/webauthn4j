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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;

public class AAGUIDDeserializer extends StdDeserializer<AAGUID> {

    public AAGUIDDeserializer() {
        super(AAGUID.class);
    }

    @Override
    public @NotNull AAGUID deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        return new AAGUID(p.getBinaryValue());
    }
}
