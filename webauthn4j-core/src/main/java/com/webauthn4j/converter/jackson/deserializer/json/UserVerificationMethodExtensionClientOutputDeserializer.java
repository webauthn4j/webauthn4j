package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.UvmEntries;
import com.webauthn4j.data.extension.client.UserVerificationMethodExtensionClientOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class UserVerificationMethodExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<UserVerificationMethodExtensionClientOutput> {

    public UserVerificationMethodExtensionClientOutputDeserializer() {
        super(UserVerificationMethodExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(UserVerificationMethodExtensionClientOutput.KEY_UVM);
    }

    @Override
    public UserVerificationMethodExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(UserVerificationMethodExtensionClientOutput.KEY_UVM);
        if (value == null || value.isNull()) return null;
        UvmEntries uvmEntries = ctxt.readTreeAsValue(value, UvmEntries.class);
        return new UserVerificationMethodExtensionClientOutput(uvmEntries);
    }
}
