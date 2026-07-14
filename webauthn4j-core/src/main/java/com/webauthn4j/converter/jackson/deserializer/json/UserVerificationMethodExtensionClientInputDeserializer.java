package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.UserVerificationMethodExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class UserVerificationMethodExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<UserVerificationMethodExtensionClientInput> {

    public UserVerificationMethodExtensionClientInputDeserializer() {
        super(UserVerificationMethodExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(UserVerificationMethodExtensionClientInput.KEY_UVM);
    }

    @Override
    public UserVerificationMethodExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(UserVerificationMethodExtensionClientInput.KEY_UVM);
        if (value == null || value.isNull()) return null;
        return new UserVerificationMethodExtensionClientInput(value.asBoolean());
    }
}
