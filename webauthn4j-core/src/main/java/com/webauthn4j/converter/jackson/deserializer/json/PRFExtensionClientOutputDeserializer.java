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

import com.webauthn4j.data.extension.client.AuthenticationExtensionsPRFOutputs;
import com.webauthn4j.data.extension.client.PRFExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class PRFExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<PRFExtensionClientOutput> {

    public PRFExtensionClientOutputDeserializer() {
        super(PRFExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(PRFExtensionClientOutput.KEY_PRF);
    }

    @Override
    public PRFExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode prfNode = node.get(PRFExtensionClientOutput.KEY_PRF);
        if (prfNode == null || prfNode.isNull() || !prfNode.isObject()) return null;
        AuthenticationExtensionsPRFOutputs outputs = ctxt.readTreeAsValue(prfNode, AuthenticationExtensionsPRFOutputs.class);
        return new PRFExtensionClientOutput(outputs);
    }
}
