package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.client.CredentialPropertiesExtensionClientOutput;
import com.webauthn4j.data.extension.client.CredentialPropertiesOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class CredentialPropertiesExtensionClientOutputDeserializer extends ExtensionClientOutputDeserializer<CredentialPropertiesExtensionClientOutput> {

    public CredentialPropertiesExtensionClientOutputDeserializer() {
        super(CredentialPropertiesExtensionClientOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(CredentialPropertiesExtensionClientOutput.KEY_CRED_PROPS);
    }

    @Override
    public CredentialPropertiesExtensionClientOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(CredentialPropertiesExtensionClientOutput.KEY_CRED_PROPS);
        if (value == null || value.isNull()) return null;
        CredentialPropertiesOutput credProps = ctxt.readTreeAsValue(value, CredentialPropertiesOutput.class);
        return new CredentialPropertiesExtensionClientOutput(credProps);
    }
}
