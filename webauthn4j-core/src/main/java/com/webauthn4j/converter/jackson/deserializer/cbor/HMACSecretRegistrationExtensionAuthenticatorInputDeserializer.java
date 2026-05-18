package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.data.extension.authenticator.HMACSecretRegistrationExtensionAuthenticatorInput;
import org.jetbrains.annotations.NotNull;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.Set;

public class HMACSecretRegistrationExtensionAuthenticatorInputDeserializer extends ExtensionAuthenticatorInputDeserializer<HMACSecretRegistrationExtensionAuthenticatorInput> {

    public HMACSecretRegistrationExtensionAuthenticatorInputDeserializer() {
        super(HMACSecretRegistrationExtensionAuthenticatorInput.class);
    }

    @Override
    public @NotNull Set<String> getKeys() {
        return Set.of(HMACSecretRegistrationExtensionAuthenticatorInput.KEY_HMAC_SECRET);
    }

    @Override
    public HMACSecretRegistrationExtensionAuthenticatorInput deserialize(JsonParser p, DeserializationContext ctxt) {
        ObjectNode node = (ObjectNode) p.readValueAsTree();
        JsonNode value = node.get(HMACSecretRegistrationExtensionAuthenticatorInput.KEY_HMAC_SECRET);
        if (value == null || value.isNull()) return null;
        if (!value.isBoolean()) return null;
        return new HMACSecretRegistrationExtensionAuthenticatorInput(value.asBoolean());
    }
}
