/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter.jackson.deserializer.json;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.util.Base64Util;

import java.io.IOException;

public class ByteArrayBase64Deserializer extends StdDeserializer<byte[]> {

    public ByteArrayBase64Deserializer() {
        super(byte[].class);
    }

    @Override
    public byte[] deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        return Base64Util.decode(p.getValueAsString());
    }
}
