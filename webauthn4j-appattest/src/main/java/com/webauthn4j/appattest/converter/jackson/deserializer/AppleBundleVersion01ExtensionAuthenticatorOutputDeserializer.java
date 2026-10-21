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

import com.webauthn4j.appattest.data.extension.AppleBundleVersion01ExtensionAuthenticatorOutput;
import com.webauthn4j.converter.jackson.deserializer.cbor.ExtensionAuthenticatorOutputDeserializer;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class AppleBundleVersion01ExtensionAuthenticatorOutputDeserializer
        extends ExtensionAuthenticatorOutputDeserializer<AppleBundleVersion01ExtensionAuthenticatorOutput> {

    public AppleBundleVersion01ExtensionAuthenticatorOutputDeserializer() {
        super(AppleBundleVersion01ExtensionAuthenticatorOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(AppleBundleVersion01ExtensionAuthenticatorOutput.ID);
    }

    @Override
    public AppleBundleVersion01ExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(AppleBundleVersion01ExtensionAuthenticatorOutput.ID);
        if (value == null || value.isNull()) return null;
        return new AppleBundleVersion01ExtensionAuthenticatorOutput(value.textValue());
    }
}
