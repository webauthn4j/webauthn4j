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
import com.webauthn4j.attestation.statement.JWS;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JWSSerializer extends StdSerializer<JWS> {

    public JWSSerializer() {
        super(JWS.class);
    }

    @Override
    public void serialize(JWS value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        String data = value.getHeaderString() + "." + value.getPayloadString() + "." + Base64.getEncoder().encodeToString(value.getSignature());
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        gen.writeBinary(bytes);
    }
}
