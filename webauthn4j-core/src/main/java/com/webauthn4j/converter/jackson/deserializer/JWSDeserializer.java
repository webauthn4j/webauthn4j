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
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.statement.Response;
import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSFactory;
import com.webauthn4j.util.AssertUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Jackson Deserializer for {@link JWS}
 */
public class JWSDeserializer extends StdDeserializer<JWS> {

    private JWSFactory jwsFactory;

    public JWSDeserializer(JsonConverter jsonConverter) {
        super(JWS.class);

        AssertUtil.notNull(jsonConverter, "jsonConverter must not be null");

        this.jwsFactory = new JWSFactory(jsonConverter);
    }

    @Override
    public JWS deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        byte[] value = p.getBinaryValue();
        String str = new String(value, StandardCharsets.UTF_8);
        try {
            return jwsFactory.parse(str, Response.class);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(p, "value is not valid as JWS", value, JWS.class);
        }
    }
}
