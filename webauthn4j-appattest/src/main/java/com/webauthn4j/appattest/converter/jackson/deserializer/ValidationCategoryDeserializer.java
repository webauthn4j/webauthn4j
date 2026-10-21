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

package com.webauthn4j.appattest.converter.jackson.deserializer;

import com.webauthn4j.appattest.data.ValidationCategory;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ValidationCategoryDeserializer extends StdDeserializer<ValidationCategory> {

    public ValidationCategoryDeserializer() {
        super(ValidationCategory.class);
    }

    @Override
    public ValidationCategory deserialize(JsonParser p, DeserializationContext ctxt) {
        JsonNode node = p.readValueAsTree();
        if (!node.isBinary()) {
            return ctxt.reportInputMismatch(ValidationCategory.class, "validation category must be a CBOR byte string");
        }
        byte[] bytes = node.binaryValue();
        if (bytes.length != Integer.BYTES) {
            return ctxt.reportInputMismatch(ValidationCategory.class, "validation category must contain exactly 4 bytes");
        }
        return ValidationCategory.create(Integer.toUnsignedLong(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt()));
    }
}
