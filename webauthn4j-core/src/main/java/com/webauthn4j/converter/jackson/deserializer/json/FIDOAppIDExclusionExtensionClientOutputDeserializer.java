package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.FIDOAppIDExclusionExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class FIDOAppIDExclusionExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<FIDOAppIDExclusionExtensionClientOutput> {

    public FIDOAppIDExclusionExtensionClientOutputDeserializer() {
        super(FIDOAppIDExclusionExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(FIDOAppIDExclusionExtensionClientOutput.KEY_APPID_EXCLUDE);
    }

    @Override
    public FIDOAppIDExclusionExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(FIDOAppIDExclusionExtensionClientOutput.KEY_APPID_EXCLUDE);
        if (value == null || value.isNull()) return null;
        return new FIDOAppIDExclusionExtensionClientOutput(value.asBoolean());
    }
}
