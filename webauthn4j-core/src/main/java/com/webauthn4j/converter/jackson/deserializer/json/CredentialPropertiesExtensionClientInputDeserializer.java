package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.CredentialPropertiesExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class CredentialPropertiesExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<CredentialPropertiesExtensionClientInput> {

    public CredentialPropertiesExtensionClientInputDeserializer() {
        super(CredentialPropertiesExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(CredentialPropertiesExtensionClientInput.KEY_CRED_PROPS);
    }

    @Override
    public CredentialPropertiesExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(CredentialPropertiesExtensionClientInput.KEY_CRED_PROPS);
        if (value == null || value.isNull()) return null;
        return new CredentialPropertiesExtensionClientInput(value.asBoolean());
    }
}
