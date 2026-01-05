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

package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.AttachmentHint;
import com.webauthn4j.data.KeyProtectionType;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.deser.std.StdDeserializer;
import tools.jackson.databind.exc.InvalidFormatException;

public class KeyProtectionTypeFromIntDeserializer extends StdDeserializer<KeyProtectionType> {

    public KeyProtectionTypeFromIntDeserializer() {
        super(KeyProtectionType.class);
    }

    @Override
    public KeyProtectionType deserialize(@NotNull JsonParser p, @NotNull DeserializationContext ctxt) {
        int value = p.getValueAsInt();
        try {
            return KeyProtectionType.create(value);
        } catch (IllegalArgumentException e) {
            throw new InvalidFormatException(null, "value is out of range", value, AttachmentHint.class);
        }
    }
}
