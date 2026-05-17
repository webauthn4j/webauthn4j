package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.FIDOAppIDExclusionExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class FIDOAppIDExclusionExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<FIDOAppIDExclusionExtensionClientInput> {

    public FIDOAppIDExclusionExtensionClientInputDeserializer() {
        super(FIDOAppIDExclusionExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(FIDOAppIDExclusionExtensionClientInput.KEY_APPID_EXCLUDE);
    }

    @Override
    public FIDOAppIDExclusionExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(FIDOAppIDExclusionExtensionClientInput.KEY_APPID_EXCLUDE);
        if (value == null || value.isNull()) return null;
        return new FIDOAppIDExclusionExtensionClientInput(value.textValue());
    }
}
