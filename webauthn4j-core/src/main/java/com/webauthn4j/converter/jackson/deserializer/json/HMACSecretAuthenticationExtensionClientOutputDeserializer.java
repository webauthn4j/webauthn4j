package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.client.HMACSecretAuthenticationExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretAuthenticationExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<HMACSecretAuthenticationExtensionClientOutput> {

    public HMACSecretAuthenticationExtensionClientOutputDeserializer() {
        super(HMACSecretAuthenticationExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretAuthenticationExtensionClientOutput.KEY_HMAC_GET_SECRET);
    }

    @Override
    public HMACSecretAuthenticationExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(HMACSecretAuthenticationExtensionClientOutput.KEY_HMAC_GET_SECRET);
        if (value == null || value.isNull()) return null;
        HMACGetSecretOutput hmacGetSecret = ctxt.readTreeAsValue(value, HMACGetSecretOutput.class);
        return new HMACSecretAuthenticationExtensionClientOutput(hmacGetSecret);
    }
}
