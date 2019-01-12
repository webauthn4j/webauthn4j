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
import com.webauthn4j.request.extension.client.ExtensionClientInput;
import com.webauthn4j.request.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.request.extension.client.SupportedExtensionsExtensionClientInput;
import com.webauthn4j.response.extension.client.*;

import java.io.IOException;

/**
 * Jackson Deserializer for {@link ExtensionClientOutput}
 */
public class ExtensionClientInputDeserializer extends StdDeserializer<ExtensionClientInput> {

    public ExtensionClientInputDeserializer() {
        super(ExtensionClientInput.class);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

        String currentName = p.getParsingContext().getCurrentName();

        if (currentName != null) {
            switch (currentName) {
                case FIDOAppIDExtensionClientInput.ID:
                    return ctxt.readValue(p, FIDOAppIDExtensionClientInput.class);
                default:
                    throw new InvalidFormatException(p, "value is out of range", currentName, ExtensionClientInput.class);
            }
        } else {
            String parentName = p.getParsingContext().getParent().getCurrentName();

            switch (parentName) {
                case SupportedExtensionsExtensionClientInput.ID:
                    return ctxt.readValue(p, SupportedExtensionsExtensionClientInput.class);

                default:
                    throw new InvalidFormatException(p, "value is out of range", parentName, ExtensionClientInput.class);
            }
        }
    }
}
