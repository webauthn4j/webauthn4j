package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class FIDOAppIDExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<FIDOAppIDExtensionClientOutput> {

    public FIDOAppIDExtensionClientOutputDeserializer() {
        super(FIDOAppIDExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(FIDOAppIDExtensionClientOutput.KEY_APPID);
    }

    @Override
    public FIDOAppIDExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(FIDOAppIDExtensionClientOutput.KEY_APPID);
        if (value == null || value.isNull()) return null;
        return new FIDOAppIDExtensionClientOutput(value.asBoolean());
    }
}
