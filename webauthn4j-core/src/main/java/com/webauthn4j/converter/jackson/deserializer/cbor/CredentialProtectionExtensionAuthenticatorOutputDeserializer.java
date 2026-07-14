package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.CredentialProtectionPolicy;
import com.webauthn4j.data.extension.authenticator.CredentialProtectionExtensionAuthenticatorOutput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class CredentialProtectionExtensionAuthenticatorOutputDeserializer extends ExtensionAuthenticatorOutputDeserializer<CredentialProtectionExtensionAuthenticatorOutput> {

    public CredentialProtectionExtensionAuthenticatorOutputDeserializer() {
        super(CredentialProtectionExtensionAuthenticatorOutput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(CredentialProtectionExtensionAuthenticatorOutput.KEY_CRED_PROTECT);
    }

    @Override
    public CredentialProtectionExtensionAuthenticatorOutput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = p.readValueAsTree();
        JsonNode value = node.get(CredentialProtectionExtensionAuthenticatorOutput.KEY_CRED_PROTECT);
        if (value == null || value.isNull()) return null;
        CredentialProtectionPolicy policy = ctxt.readTreeAsValue(value, CredentialProtectionPolicy.class);
        return new CredentialProtectionExtensionAuthenticatorOutput(policy);
    }
}
