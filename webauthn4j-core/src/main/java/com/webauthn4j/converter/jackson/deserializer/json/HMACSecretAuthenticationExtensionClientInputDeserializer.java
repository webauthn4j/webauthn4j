package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.HMACGetSecretInput;
import com.webauthn4j.data.extension.client.HMACSecretAuthenticationExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretAuthenticationExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<HMACSecretAuthenticationExtensionClientInput> {

    public HMACSecretAuthenticationExtensionClientInputDeserializer() {
        super(HMACSecretAuthenticationExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretAuthenticationExtensionClientInput.KEY_HMAC_GET_SECRET);
    }

    @Override
    public HMACSecretAuthenticationExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(HMACSecretAuthenticationExtensionClientInput.KEY_HMAC_GET_SECRET);
        if (value == null || value.isNull()) return null;
        HMACGetSecretInput hmacGetSecret = ctxt.readTreeAsValue(value, HMACGetSecretInput.class);
        return new HMACSecretAuthenticationExtensionClientInput(hmacGetSecret);
    }
}
