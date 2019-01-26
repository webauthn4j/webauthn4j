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

package com.webauthn4j.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.webauthn4j.registry.Registry;
import com.webauthn4j.util.jws.JWS;
import com.webauthn4j.util.jws.JWSHeader;
import com.webauthn4j.response.attestation.statement.Response;
import com.webauthn4j.util.Base64UrlUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWSDeserializer extends StdDeserializer<JWS> {

    private transient Registry registry;

    public JWSDeserializer(Registry registry) {
        super(JWS.class);
        this.registry = registry;
    }

    @Override
    public JWS deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        byte[] value = p.getBinaryValue();
        String str = new String(value, StandardCharsets.UTF_8);
        String[] data = str.split("\\.");
        if (data.length != 3) {
            throw new InvalidFormatException(p, "Invalid JWS", value, JWS.class);
        }
        String headerString = data[0];
        String payloadString = data[1];
        String signatureString = data[2];
        try {
            JWSHeader header = registry.getJsonMapper().readValue(Base64UrlUtil.decode(headerString), JWSHeader.class);
            Response payload = registry.getJsonMapper().readValue(Base64UrlUtil.decode(payloadString), Response.class);
            byte[] signature = Base64UrlUtil.decode(signatureString);
            return new JWS(header, headerString, payload, payloadString, signature);
        } catch (IOException e) {
            throw new InvalidFormatException(p, "Invalid JWS", value, JWS.class);
        }
    }
}
