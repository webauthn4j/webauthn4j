/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.metadata.converter.jackson.serializer;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Jackson Serializer for {@link AAGUID} in Metadata JSON format.
 * Serializes AAGUID as a UUID string (e.g. "33c1642b-b5e9-423d-9add-5a0119c2a8b8").
 */
public class MetadataAAGUIDSerializer extends StdSerializer<AAGUID> {

    public MetadataAAGUIDSerializer() {
        super(AAGUID.class);
    }

    @Override
    public void serialize(@NotNull AAGUID value, @NotNull JsonGenerator gen, @NotNull SerializationContext provider) {
        AssertUtil.notNull(value, "value is null");
        gen.writeString(value.toString());
    }
}
