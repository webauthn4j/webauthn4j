package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.client.CredentialProtectionExtensionClientInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

/**
 * Deserializer for the credProtect extension client input.
 * This is a 2-key extension: "credentialProtectionPolicy" and "enforceCredentialProtectionPolicy"
 * map to a single {@link CredentialProtectionExtensionClientInput}.
 */
public class CredentialProtectionExtensionClientInputDeserializer extends ExtensionClientInputDeserializer<CredentialProtectionExtensionClientInput> {

    public CredentialProtectionExtensionClientInputDeserializer() {
        super(CredentialProtectionExtensionClientInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(CredentialProtectionExtensionClientInput.KEY_CREDENTIAL_PROTECTION_POLICY, CredentialProtectionExtensionClientInput.KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY);
    }

    @Override
    public CredentialProtectionExtensionClientInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode policyNode = node.get(CredentialProtectionExtensionClientInput.KEY_CREDENTIAL_PROTECTION_POLICY);
        JsonNode enforceNode = node.get(CredentialProtectionExtensionClientInput.KEY_ENFORCE_CREDENTIAL_PROTECTION_POLICY);
        if (policyNode == null && enforceNode == null) return null;
        CredentialProtectionPolicy policy = policyNode != null
                ? ctxt.readTreeAsValue(policyNode, CredentialProtectionPolicy.class) : null;
        Boolean enforce = enforceNode != null ? enforceNode.asBoolean() : null;
        return new CredentialProtectionExtensionClientInput(policy, enforce);
    }
}
