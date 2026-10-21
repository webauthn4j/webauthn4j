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

package com.webauthn4j.appattest.converter.jackson.serializer;

import com.webauthn4j.appattest.data.ValidationCategory;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ValidationCategorySerializer extends StdSerializer<ValidationCategory> {

    public ValidationCategorySerializer() {
        super(ValidationCategory.class);
    }

    @Override
    public void serialize(ValidationCategory value, JsonGenerator gen, SerializationContext provider) {
        gen.writeBinary(ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt((int) value.getValue()).array());
    }
}
