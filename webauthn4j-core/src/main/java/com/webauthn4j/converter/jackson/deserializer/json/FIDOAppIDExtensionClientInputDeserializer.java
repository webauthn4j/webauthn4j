package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class FIDOAppIDExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<FIDOAppIDExtensionClientInput> {

    public FIDOAppIDExtensionClientInputDeserializer() {
        super(FIDOAppIDExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(FIDOAppIDExtensionClientInput.KEY_APPID);
    }

    @Override
    public FIDOAppIDExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(FIDOAppIDExtensionClientInput.KEY_APPID);
        if (value == null || value.isNull()) return null;
        return new FIDOAppIDExtensionClientInput(value.textValue());
    }
}
