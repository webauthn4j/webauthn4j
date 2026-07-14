package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.HMACSecretRegistrationExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretRegistrationExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<HMACSecretRegistrationExtensionClientOutput> {

    public HMACSecretRegistrationExtensionClientOutputDeserializer() {
        super(HMACSecretRegistrationExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretRegistrationExtensionClientOutput.KEY_HMAC_CREATE_SECRET);
    }

    @Override
    public HMACSecretRegistrationExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(HMACSecretRegistrationExtensionClientOutput.KEY_HMAC_CREATE_SECRET);
        if (value == null || value.isNull()) return null;
        return new HMACSecretRegistrationExtensionClientOutput(value.asBoolean());
    }
}
