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

import com.webauthn4j.data.extension.client.AuthenticationExtensionsLargeBlobOutputs;
import com.webauthn4j.data.extension.client.LargeBlobExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class LargeBlobExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<LargeBlobExtensionClientOutput> {

    public LargeBlobExtensionClientOutputDeserializer() {
        super(LargeBlobExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(LargeBlobExtensionClientOutput.KEY_LARGE_BLOB);
    }

    @Override
    public LargeBlobExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode largeBlobNode = node.get(LargeBlobExtensionClientOutput.KEY_LARGE_BLOB);
        if (largeBlobNode == null || largeBlobNode.isNull() || !largeBlobNode.isObject()) return null;
        AuthenticationExtensionsLargeBlobOutputs outputs = ctxt.readTreeAsValue(largeBlobNode, AuthenticationExtensionsLargeBlobOutputs.class);
        return new LargeBlobExtensionClientOutput(outputs);
    }
}
