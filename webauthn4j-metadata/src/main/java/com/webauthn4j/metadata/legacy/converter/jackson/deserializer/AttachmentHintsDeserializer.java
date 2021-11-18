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

package com.webauthn4j.metadata.legacy.converter.jackson.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.webauthn4j.metadata.legacy.data.statement.AttachmentHints;

import java.io.IOException;

public class AttachmentHintsDeserializer extends StdDeserializer<AttachmentHints> {

    public AttachmentHintsDeserializer() {
        super(AttachmentHints.class);
    }

    @Override
    public AttachmentHints deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        return new AttachmentHints(p.getLongValue());
    }
}
