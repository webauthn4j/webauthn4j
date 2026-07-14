package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.authenticator.CredentialProtectionExtensionAuthenticatorInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class CredentialProtectionExtensionAuthenticatorInputDeserializer extends ExtensionAuthenticatorInputDeserializer<CredentialProtectionExtensionAuthenticatorInput> {

    public CredentialProtectionExtensionAuthenticatorInputDeserializer() {
        super(CredentialProtectionExtensionAuthenticatorInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(CredentialProtectionExtensionAuthenticatorInput.KEY_CRED_PROTECT);
    }

    @Override
    public CredentialProtectionExtensionAuthenticatorInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(CredentialProtectionExtensionAuthenticatorInput.KEY_CRED_PROTECT);
        if (value == null || value.isNull()) return null;
        CredentialProtectionPolicy policy = ctxt.readTreeAsValue(value, CredentialProtectionPolicy.class);
        return new CredentialProtectionExtensionAuthenticatorInput(policy);
    }
}
