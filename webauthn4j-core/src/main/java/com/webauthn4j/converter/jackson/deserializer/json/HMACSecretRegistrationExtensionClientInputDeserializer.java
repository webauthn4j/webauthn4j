package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.HMACSecretRegistrationExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretRegistrationExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<HMACSecretRegistrationExtensionClientInput> {

    public HMACSecretRegistrationExtensionClientInputDeserializer() {
        super(HMACSecretRegistrationExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretRegistrationExtensionClientInput.KEY_HMAC_CREATE_SECRET);
    }

    @Override
    public HMACSecretRegistrationExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(HMACSecretRegistrationExtensionClientInput.KEY_HMAC_CREATE_SECRET);
        if (value == null || value.isNull()) return null;
        return new HMACSecretRegistrationExtensionClientInput(value.asBoolean());
    }
}
