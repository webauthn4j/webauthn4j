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

import com.webauthn4j.data.attestation.statement.TPMSAttest;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

/**
 * Jackson Serializer for {@link TPMSAttest}
 */
public class TPMSAttestSerializer extends StdSerializer<TPMSAttest> {
    public TPMSAttestSerializer() {
        super(TPMSAttest.class);
    }

    @Override
    public void serialize(@NotNull TPMSAttest value, @NotNull JsonGenerator gen, @NotNull SerializationContext provider) {
        gen.writeBinary(value.getBytes());
    }

}
